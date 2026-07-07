import { execFile } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import type { Finding, ScanRequest } from '@safeweave/common';

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
              license: (info.licenses as string) || 'UNKNOWN',
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

export async function runLicenseCheck(request: ScanRequest): Promise<Finding[]> {
  const rootDir = request.context.rootDir || process.cwd();
  const blockedLicenses = (request.profile.rules as Record<string, unknown>)?.blocked_licenses as string[]
    || DEFAULT_BLOCKED_LICENSES;

  const hasNpm = existsSync(join(rootDir, 'package.json'));
  const hasPython = existsSync(join(rootDir, 'requirements.txt'))
    || existsSync(join(rootDir, 'Pipfile'))
    || existsSync(join(rootDir, 'pyproject.toml'));

  const promises: Promise<LicenseEntry[]>[] = [];
  if (hasNpm) promises.push(runNpmLicenseChecker(rootDir));
  if (hasPython) promises.push(runPipLicenses(rootDir));

  const results = await Promise.allSettled(promises);
  const allEntries: LicenseEntry[] = [];
  for (const result of results) {
    if (result.status === 'fulfilled') {
      allEntries.push(...result.value);
    }
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

  return findings;
}
