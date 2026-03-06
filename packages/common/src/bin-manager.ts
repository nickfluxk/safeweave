import { execFile } from 'node:child_process';
import { createWriteStream, mkdirSync, existsSync, chmodSync, writeFileSync, readFileSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { homedir, platform, arch } from 'node:os';
import { get as httpsGet } from 'node:https';
import { get as httpGet, type IncomingMessage } from 'node:http';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const BIN_DIR = join(homedir(), '.safeweave', 'bin');
const META_DIR = join(homedir(), '.safeweave', 'meta');

const TOOL_VERSIONS: Record<string, string> = {
  gitleaks: '8.21.2',
  trivy: '0.58.0',
  opengrep: '1.16.3',
};

type Platform = 'darwin' | 'linux' | 'win32';
type Arch = 'arm64' | 'x64';

// ---------------------------------------------------------------------------
// URL builders
// ---------------------------------------------------------------------------

function gitleaksUrl(version: string, plat: Platform, architecture: Arch): string {
  const os = plat === 'win32' ? 'windows' : plat;
  const ext = plat === 'win32' ? 'zip' : 'tar.gz';
  return `https://github.com/gitleaks/gitleaks/releases/download/v${version}/gitleaks_${version}_${os}_${architecture}.${ext}`;
}

function trivyUrl(version: string, plat: Platform, architecture: Arch): string {
  let os: string;
  let ar: string;
  if (plat === 'darwin') {
    os = 'macOS';
    ar = architecture === 'arm64' ? 'ARM64' : '64bit';
  } else if (plat === 'win32') {
    os = 'windows';
    ar = '64bit';
  } else {
    os = 'Linux';
    ar = architecture === 'arm64' ? 'ARM64' : '64bit';
  }
  const ext = plat === 'win32' ? 'zip' : 'tar.gz';
  return `https://github.com/aquasecurity/trivy/releases/download/v${version}/trivy_${version}_${os}-${ar}.${ext}`;
}

function opengrepUrl(version: string, plat: Platform, architecture: Arch): string {
  if (plat === 'darwin') {
    const ar = architecture === 'arm64' ? 'arm64' : 'x86';
    return `https://github.com/opengrep/opengrep/releases/download/v${version}/opengrep_osx_${ar}`;
  }
  if (plat === 'win32') {
    return `https://github.com/opengrep/opengrep/releases/download/v${version}/opengrep_windows_x86.exe`;
  }
  // linux
  const ar = architecture === 'arm64' ? 'aarch64' : 'x86';
  return `https://github.com/opengrep/opengrep/releases/download/v${version}/opengrep_manylinux_${ar}`;
}

interface ToolDef {
  getUrl: (version: string, plat: Platform, architecture: Arch) => string;
  /** Binary name inside the archive (without .exe). Opengrep has no archive. */
  archiveBinary: string | null;
}

const TOOLS: Record<string, ToolDef> = {
  gitleaks: { getUrl: gitleaksUrl, archiveBinary: 'gitleaks' },
  trivy: { getUrl: trivyUrl, archiveBinary: 'trivy' },
  opengrep: { getUrl: opengrepUrl, archiveBinary: null }, // raw binary, no archive
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function log(msg: string): void {
  process.stderr.write(`[SafeWeave] ${msg}\n`);
}

function getPlatform(): Platform {
  const p = platform();
  if (p === 'darwin' || p === 'linux' || p === 'win32') return p;
  throw new Error(`Unsupported platform: ${p}`);
}

function getArch(): Arch {
  const a = arch();
  if (a === 'arm64') return 'arm64';
  return 'x64'; // x64, ia32, etc. → x64
}

function binName(tool: string): string {
  const isWin = platform() === 'win32';
  return isWin ? `${tool}.exe` : tool;
}

/** Check if a command exists on the system PATH */
function systemBinaryPath(cmd: string): Promise<string | null> {
  return new Promise((resolve) => {
    const which = platform() === 'win32' ? 'where' : 'which';
    execFile(which, [cmd], (err, stdout) => {
      if (err || !stdout.trim()) {
        resolve(null);
      } else {
        resolve(stdout.trim().split('\n')[0]);
      }
    });
  });
}

// ---------------------------------------------------------------------------
// Download helpers (zero npm deps — Node.js built-ins only)
// ---------------------------------------------------------------------------

function followRedirects(url: string, maxRedirects = 5): Promise<IncomingMessage> {
  return new Promise((resolve, reject) => {
    const getter = url.startsWith('https') ? httpsGet : httpGet;
    getter(url, (res) => {
      if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        if (maxRedirects <= 0) return reject(new Error('Too many redirects'));
        resolve(followRedirects(res.headers.location, maxRedirects - 1));
      } else if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
        resolve(res);
      } else {
        reject(new Error(`HTTP ${res.statusCode} downloading ${url}`));
      }
    }).on('error', reject);
  });
}

function downloadFile(url: string, dest: string): Promise<void> {
  return new Promise(async (resolve, reject) => {
    try {
      const res = await followRedirects(url);
      const ws = createWriteStream(dest);
      res.pipe(ws);
      ws.on('finish', () => { ws.close(); resolve(); });
      ws.on('error', reject);
    } catch (err) {
      reject(err);
    }
  });
}

function extractTarGz(archive: string, binaryName: string, outDir: string): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile('tar', ['xzf', archive, '-C', outDir], (err) => {
      if (err) return reject(new Error(`tar extraction failed: ${err.message}`));
      const outPath = join(outDir, binaryName);
      if (!existsSync(outPath)) {
        return reject(new Error(`Binary "${binaryName}" not found after extraction`));
      }
      chmodSync(outPath, 0o755);
      resolve(outPath);
    });
  });
}

function extractZip(archive: string, binaryName: string, outDir: string): Promise<string> {
  return new Promise((resolve, reject) => {
    // PowerShell Expand-Archive
    const cmd = `Expand-Archive -Path "${archive}" -DestinationPath "${outDir}" -Force`;
    execFile('powershell', ['-Command', cmd], (err) => {
      if (err) return reject(new Error(`zip extraction failed: ${err.message}`));
      const outPath = join(outDir, binaryName);
      if (!existsSync(outPath)) {
        return reject(new Error(`Binary "${binaryName}" not found after extraction`));
      }
      resolve(outPath);
    });
  });
}

// ---------------------------------------------------------------------------
// Download + install pipeline
// ---------------------------------------------------------------------------

/** In-flight downloads to avoid concurrent fetches of the same tool */
const downloadInFlight = new Map<string, Promise<string | null>>();

async function downloadAndInstall(tool: string): Promise<string | null> {
  const def = TOOLS[tool];
  if (!def) return null;
  const version = TOOL_VERSIONS[tool];
  if (!version) return null;

  const plat = getPlatform();
  const ar = getArch();
  const url = def.getUrl(version, plat, ar);
  const binary = binName(tool);
  const destBin = join(BIN_DIR, binary);

  log(`Downloading ${tool} v${version} for ${plat}/${ar}...`);

  mkdirSync(BIN_DIR, { recursive: true });
  mkdirSync(META_DIR, { recursive: true });

  try {
    if (def.archiveBinary === null) {
      // Raw binary download (opengrep)
      await downloadFile(url, destBin);
      if (plat !== 'win32') {
        chmodSync(destBin, 0o755);
      }
    } else {
      // Archive download
      const ext = plat === 'win32' ? 'zip' : 'tar.gz';
      const archivePath = join(BIN_DIR, `${tool}-archive.${ext}`);
      await downloadFile(url, archivePath);

      const archiveBinName = plat === 'win32' ? `${def.archiveBinary}.exe` : def.archiveBinary;
      if (ext === 'tar.gz') {
        await extractTarGz(archivePath, archiveBinName, BIN_DIR);
      } else {
        await extractZip(archivePath, archiveBinName, BIN_DIR);
      }

      // Clean up archive
      try { unlinkSync(archivePath); } catch { /* ignore */ }
    }

    // Write metadata
    const meta = {
      version,
      platform: plat,
      arch: ar,
      installedAt: new Date().toISOString(),
    };
    writeFileSync(join(META_DIR, `${tool}.json`), JSON.stringify(meta, null, 2));

    log(`${tool} installed → ~/.safeweave/bin/${binary}`);
    return destBin;
  } catch (err) {
    log(`Failed to download ${tool}: ${(err as Error).message}`);
    // Clean up partial download
    try { unlinkSync(destBin); } catch { /* ignore */ }
    return null;
  }
}

// ---------------------------------------------------------------------------
// Version check
// ---------------------------------------------------------------------------

function isCachedVersionCurrent(tool: string): boolean {
  const metaPath = join(META_DIR, `${tool}.json`);
  if (!existsSync(metaPath)) return false;
  try {
    const meta = JSON.parse(readFileSync(metaPath, 'utf-8'));
    return meta.version === TOOL_VERSIONS[tool];
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Resolve a scanner binary: system PATH → cached ~/.safeweave/bin/ → auto-download.
 * Returns the absolute path to the binary, or null if unavailable.
 */
export async function resolveBinary(toolName: string): Promise<string | null> {
  // 1. Check system PATH
  const systemPath = await systemBinaryPath(toolName);
  if (systemPath) return systemPath;

  // 2. Check cached binary
  const cachedPath = join(BIN_DIR, binName(toolName));
  if (existsSync(cachedPath) && isCachedVersionCurrent(toolName)) {
    return cachedPath;
  }

  // 3. Auto-download (deduplicated)
  if (!TOOLS[toolName]) return null;

  let inflight = downloadInFlight.get(toolName);
  if (!inflight) {
    inflight = downloadAndInstall(toolName);
    downloadInFlight.set(toolName, inflight);
    inflight.finally(() => downloadInFlight.delete(toolName));
  }
  return inflight;
}

/**
 * Pre-download missing binaries in parallel. Fire-and-forget.
 */
export async function ensureBinaries(names: string[]): Promise<void> {
  await Promise.allSettled(names.map((n) => resolveBinary(n)));
}
