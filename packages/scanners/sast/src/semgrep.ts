import { execFile } from 'node:child_process';
import { writeFileSync, mkdtempSync, mkdirSync, rmSync, existsSync, statSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import type { ScanRequest, Finding } from '@safeweave/common';

// Rules directory is at /app/rules in the Docker container, or relative to dist/ locally
const CUSTOM_RULES_PATHS = [
  '/app/rules',
  join(process.cwd(), 'rules'),
];

export async function runSemgrep(request: ScanRequest): Promise<Finding[]> {
  // If the request contains a single directory path (no content), scan it directly.
  // This handles the case where the project is mounted into the container.
  const hasContent = request.files.some(f => f.content);
  if (!hasContent && request.files.length === 1) {
    const target = request.files[0].path;
    if (existsSync(target) && statSync(target).isDirectory()) {
      return executeSemgrep(target);
    }
  }

  // Otherwise write file contents to a temp directory and scan that
  const tempDir = mkdtempSync(join(tmpdir(), 'safeweave-sast-'));

  try {
    for (const file of request.files) {
      if (file.content) {
        const filePath = join(tempDir, file.path);
        mkdirSync(dirname(filePath), { recursive: true });
        writeFileSync(filePath, file.content);
      }
    }

    const semgrepFindings = await executeSemgrep(tempDir);
    return semgrepFindings;
  } finally {
    rmSync(tempDir, { recursive: true, force: true });
  }
}

function executeSemgrep(targetDir: string): Promise<Finding[]> {
  return new Promise((resolve) => {
    const args = [
      '--json',
    ];

    // Load SafeWeave custom rule pack; fall back to --config auto
    let hasCustomRules = false;
    for (const rulesDir of CUSTOM_RULES_PATHS) {
      if (existsSync(rulesDir)) {
        args.push('--config', rulesDir);
        hasCustomRules = true;
        break;
      }
    }
    if (!hasCustomRules) {
      args.push('--config', 'auto');
    }

    args.push(targetDir);

    execFile('semgrep', args, { timeout: 300_000, maxBuffer: 10 * 1024 * 1024 }, (error, stdout) => {
      if (error && !stdout) {
        // Semgrep not installed or failed — return empty
        resolve([]);
        return;
      }

      try {
        const output = JSON.parse(stdout);
        const findings: Finding[] = (output.results || []).map((r: Record<string, unknown>) => ({
          id: `SAST-${(r.check_id as string || 'unknown').replace(/\./g, '-')}`,
          severity: mapSemgrepSeverity(r.extra as Record<string, unknown>),
          title: r.check_id as string || 'Unknown',
          description: ((r.extra as Record<string, unknown>)?.message as string) || '',
          file: (r.path as string || '').replace(targetDir + '/', ''),
          line: (r.start as Record<string, number>)?.line,
          cwe: extractCwe(r.extra as Record<string, unknown>),
          remediation: ((r.extra as Record<string, unknown>)?.fix as string) || 'Review and fix the flagged code pattern',
        }));
        resolve(findings);
      } catch {
        resolve([]);
      }
    });
  });
}

function mapSemgrepSeverity(extra: Record<string, unknown> | undefined): Finding['severity'] {
  const sev = (extra?.severity as string || '').toUpperCase();
  switch (sev) {
    case 'ERROR': return 'high';
    case 'WARNING': return 'medium';
    case 'INFO': return 'low';
    default: return 'info';
  }
}

function extractCwe(extra: Record<string, unknown> | undefined): string | undefined {
  const metadata = extra?.metadata as Record<string, unknown> | undefined;
  const cwe = metadata?.cwe as string[] | string | undefined;
  if (Array.isArray(cwe)) return cwe[0];
  if (typeof cwe === 'string') return cwe;
  return undefined;
}
