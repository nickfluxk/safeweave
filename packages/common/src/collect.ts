import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, basename } from 'node:path';

const MAX_FILES = 2000;
const MAX_TOTAL_BYTES = 50 * 1024 * 1024; // 50MB
const MAX_FILE_SIZE = 1 * 1024 * 1024; // 1MB
const MAX_DEPTH = 20;

const SKIP_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', '__pycache__', 'vendor',
  '.next', '.venv', 'coverage', '.cache', '.output', '.nuxt', '.svelte-kit',
  'target', 'out', '.turbo', '.parcel-cache',
]);

const SOURCE_EXTENSIONS = new Set([
  '.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs',
  '.py', '.go', '.java', '.rb', '.rs', '.php', '.cs', '.swift', '.kt',
  '.json', '.yaml', '.yml', '.toml', '.xml',
  '.tf', '.hcl',
  '.sh', '.bash', '.zsh',
  '.html', '.css', '.scss', '.less', '.vue', '.svelte',
  '.sql', '.graphql', '.gql', '.proto',
  '.env', '.env.example', '.env.local',
  '.gitignore', '.dockerignore', '.eslintrc', '.prettierrc',
]);

// Files to include regardless of extension
const INCLUDE_FILENAMES = new Set([
  'Dockerfile', 'Makefile', 'Gemfile', 'Rakefile', 'Procfile',
  'docker-compose.yml', 'docker-compose.yaml',
  'package.json', 'package-lock.json', 'pnpm-lock.yaml', 'yarn.lock',
  'requirements.txt', 'Pipfile', 'pyproject.toml', 'setup.py', 'setup.cfg',
  'go.mod', 'go.sum', 'Cargo.toml', 'Cargo.lock',
  'tsconfig.json', 'tsconfig.base.json',
  '.eslintrc.json', '.prettierrc.json', 'jest.config.js', 'vitest.config.ts',
]);

export interface CollectedFile {
  path: string;
  content: string;
}

/**
 * True for files that routinely hold LIVE credentials rather than source code.
 *
 * These are deliberately collected — finding a secret in a local `.env` is a
 * real result — but uploading one to a remote scanning service ships the
 * developer's production credentials off their machine. Callers that transmit
 * file content over the network must filter on this; callers scanning in-process
 * on the developer's own machine should not.
 *
 * `.env.example` / `.env.sample` / `.env.template` are conventionally committed
 * placeholders, so they stay.
 */
export function isSecretBearingFile(relPath: string): boolean {
  const base = basename(relPath).toLowerCase();
  if (base === '.env.example' || base === '.env.sample' || base === '.env.template') return false;
  return base === '.env' || base.startsWith('.env.');
}

/**
 * Walk a local directory and collect source files with their content.
 * Returns files with relative paths and content strings.
 *
 * Lives in common because both the gateway (scanning its own project dir) and
 * the CLI (which must send content, not paths, to a hosted gateway that cannot
 * see the caller's disk) need exactly this traversal.
 */
export function collectLocalFiles(rootDir: string): CollectedFile[] {
  const files: CollectedFile[] = [];
  let totalBytes = 0;

  function walk(dir: string, depth: number) {
    if (depth > MAX_DEPTH || files.length >= MAX_FILES) return;

    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      if (files.length >= MAX_FILES || totalBytes >= MAX_TOTAL_BYTES) return;

      const fullPath = join(dir, entry.name);

      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name) && !entry.name.startsWith('.')) {
          walk(fullPath, depth + 1);
        }
        continue;
      }

      if (!entry.isFile()) continue;

      // Check if file should be included. Multi-dot dotfiles like '.env.local'
      // have getExtension() return '.local', so the full filename is also
      // matched against SOURCE_EXTENSIONS — its '.env.local'/'.env.example'
      // entries are only reachable that way.
      const ext = getExtension(entry.name);
      if (!SOURCE_EXTENSIONS.has(ext) && !SOURCE_EXTENSIONS.has(entry.name) && !INCLUDE_FILENAMES.has(entry.name)) {
        continue;
      }

      try {
        const stat = statSync(fullPath);
        if (stat.size > MAX_FILE_SIZE || stat.size === 0) continue;

        const content = readFileSync(fullPath, 'utf-8');
        const relPath = relative(rootDir, fullPath);
        totalBytes += Buffer.byteLength(content);

        files.push({ path: relPath, content });
      } catch {
        // Skip unreadable files
      }
    }
  }

  walk(rootDir, 0);
  return files;
}

function getExtension(filename: string): string {
  // Dotfiles are their own extension: ".env" must match the ".env" entry in
  // SOURCE_EXTENSIONS. Treating a leading dot as "no extension" silently
  // excluded every dotfile in that set (.env, .gitignore, .eslintrc, ...),
  // so files the scanner was configured to inspect were never read.
  const lastDot = filename.lastIndexOf('.');
  if (lastDot < 0) return '';
  if (lastDot === 0) return filename;
  return filename.slice(lastDot);
}

// ---------------------------------------------------------------------------
// Repository attribution
//
// Scans are grouped per repo in the dashboard (`scan_usage.repo`, read back
// with DISTINCT ON (repo)). An unattributed or wrongly-attributed scan does not
// merely lose a label — it lands in a shared bucket where the next scan of a
// DIFFERENT repo overwrites it, so the two repos' scores get mixed up.
//
// The slug must therefore describe the CALLER's project. A hosted gateway must
// never derive it from its own filesystem: every tenant would file every repo
// under the container's basename.
// ---------------------------------------------------------------------------

/** Normalize an arbitrary string into a `scan_usage.repo` slug, or undefined. */
export function normalizeRepoSlug(input?: string | null): string | undefined {
  if (!input) return undefined;
  const slug = input.trim().toLowerCase().replace(/[^a-z0-9._/-]/g, '').slice(0, 200);
  return slug || undefined;
}

/**
 * Derive an `owner/repo` slug for a directory ON THIS MACHINE, falling back to
 * the directory name. Only meaningful where the path is the caller's own
 * checkout — a local CLI, or the stdio MCP server.
 */
export function deriveRepoSlug(projectDir: string): string | undefined {
  try {
    const cfg = readFileSync(join(projectDir, '.git', 'config'), 'utf-8');
    const m = cfg.match(/url\s*=\s*(.+)/);
    if (m) {
      const url = m[1].trim();
      // git@host:owner/repo.git | https://host/owner/repo(.git)
      const slug = url
        .replace(/^git@[^:]+:/, '')
        .replace(/^[a-z]+:\/\/[^/]+\//, '')
        .replace(/\.git$/, '')
        .trim();
      if (slug && /^[\w.\-]+\/[\w.\-]+$/.test(slug)) return slug.toLowerCase();
    }
  } catch {
    // no .git/config or unreadable — fall through to basename
  }
  const base = basename(projectDir);
  return base && base !== '.' && base !== '/' ? normalizeRepoSlug(base) : undefined;
}
