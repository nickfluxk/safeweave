import { execFile } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join } from 'node:path';

import { engineUnavailable, materializeFiles, type ScanRequest, type Finding, type ScanOutcome } from '@safeweave/common';

interface LicenseEntry {
  package: string;
  version: string;
  license: string;
  ecosystem: string;
  manifestFile: string;
}

const DEFAULT_BLOCKED_LICENSES = ['GPL-3.0', 'AGPL-3.0', 'GPL-3.0-only', 'AGPL-3.0-only'];

function runNpmLicenseChecker(rootDir: string): Promise<LicenseEntry[]> {
  return new Promise((resolve) => {
    execFile('license-checker', ['--json', '--start', rootDir],
      { timeout: 60_000, maxBuffer: 10 * 1024 * 1024 },
      (_error, stdout) => {
        if (!stdout) { resolve([]); return; }
        try {
          const data = JSON.parse(stdout);
          const entries: LicenseEntry[] = [];
          for (const [key, info] of Object.entries(data) as [string, Record<string, unknown>][]) {
            const atIdx = key.lastIndexOf('@');
            const pkg = atIdx > 0 ? key.substring(0, atIdx) : key;
            const ver = atIdx > 0 ? key.substring(atIdx + 1) : 'unknown';
            entries.push({
              package: pkg,
              version: ver,
              // license-checker emits a STRING for single licenses and an
              // ARRAY for dual-licensed packages ("licenses": ["MIT","Apache-2.0"]).
              // The old `as string` cast lied, so .toUpperCase() below threw a
              // TypeError on any dual-licensed dependency and the entire license
              // scan collapsed to zero findings — hiding real AGPL violations.
              license: normalizeLicense(info.licenses),
              ecosystem: 'npm',
              manifestFile: 'package.json',
            });
          }
          resolve(entries);
        } catch { resolve([]); }
      });
  });
}

function runPipLicenses(rootDir: string): Promise<LicenseEntry[]> {
  return new Promise((resolve) => {
    execFile('pip-licenses', ['--format=json'],
      { timeout: 60_000, cwd: rootDir },
      (_error, stdout) => {
        if (!stdout) { resolve([]); return; }
        try {
          const data = JSON.parse(stdout) as { Name: string; Version: string; License: string }[];
          const entries: LicenseEntry[] = data.map((pkg) => ({
            package: pkg.Name,
            version: pkg.Version,
            license: pkg.License,
            ecosystem: 'python',
            manifestFile: 'requirements.txt',
          }));
          resolve(entries);
        } catch { resolve([]); }
      });
  });
}

/** Collapse license-checker's string|array|missing license field to a string. */
function normalizeLicense(raw: unknown): string {
  if (Array.isArray(raw)) {
    const parts = raw.filter((x): x is string => typeof x === 'string');
    return parts.length ? parts.join(' OR ') : 'UNKNOWN';
  }
  if (typeof raw === 'string' && raw.trim()) return raw;
  return 'UNKNOWN';
}

export async function runLicenseCheck(request: ScanRequest): Promise<ScanOutcome> {
  // Scan the files sent in the request (works across hosts); fall back to
  // context.rootDir only when no file content was provided.
  const hasContent = (request.files || []).some((f) => f.content != null);
  const mat = hasContent ? materializeFiles(request.files, 'safeweave-license-') : null;
  const rootDir = mat ? mat.dir : (request.context.rootDir || process.cwd());

  try {
    return await collectLicenseFindings(request, rootDir, mat !== null);
  } finally {
    mat?.cleanup();
  }
}

async function collectLicenseFindings(
  request: ScanRequest,
  rootDir: string,
  materialized: boolean,
): Promise<ScanOutcome> {
  const blockedLicenses = (request.profile.rules as Record<string, unknown>)?.blocked_licenses as string[]
    || DEFAULT_BLOCKED_LICENSES;

  const hasNpm = existsSync(join(rootDir, 'package.json'));
  const hasPython = existsSync(join(rootDir, 'requirements.txt'))
    || existsSync(join(rootDir, 'Pipfile'))
    || existsSync(join(rootDir, 'pyproject.toml'));

  const promises: Promise<LicenseEntry[]>[] = [];
  if (hasNpm) promises.push(runNpmLicenseChecker(rootDir));
  // pip-licenses inspects the ACTIVE Python environment, not files — running it
  // against a materialized temp dir would report the scanner's own packages
  // (a false result), so only run it against a real local install.
  if (hasPython && !materialized) promises.push(runPipLicenses(rootDir));

  const results = await Promise.allSettled(promises);
  const allEntries: LicenseEntry[] = [];
  const warnings: string[] = [];
  for (const result of results) {
    if (result.status === 'fulfilled') {
      allEntries.push(...result.value);
    } else {
      // A rejected ecosystem audit means we inspected FEWER dependencies than
      // the user thinks. Dropping it silently understated their exposure.
      warnings.push(`A license audit did not complete, so results are INCOMPLETE: ${String(result.reason)}`);
    }
  }
  if (allEntries.length === 0) {
    warnings.push(engineUnavailable('license-checker', 'Install it (npm i -g license-checker) or use the SafeWeave container image.'));
  }

  const findings: Finding[] = [];
  for (const entry of allEntries) {
    const isBlocked = blockedLicenses.some((bl) =>
      entry.license.toUpperCase().includes(bl.toUpperCase())
    );
    if (isBlocked) {
      findings.push({
        id: `LICENSE-${entry.ecosystem}-${entry.package}`,
        severity: 'high',
        title: `Blocked license: ${entry.license} in ${entry.package}@${entry.version}`,
        description: `${entry.package}@${entry.version} uses ${entry.license} which is blocked by the current profile`,
        file: entry.manifestFile,
        remediation: `Replace ${entry.package} with an alternatively-licensed package`,
      });
    }
  }

  return { findings, warnings };
}
