import { execFile } from 'node:child_process';
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { engineUnavailable, materializeFiles, type ScanRequest, type Finding, type ScanOutcome } from '@safeweave/common';

// Bundled gitleaks config (default rules + SafeWeave allowlist for documented
// example secrets). Resolved relative to the package root so it works whether
// running from src (dev) or dist (build). Optional — skipped if absent.
function resolveConfigPath(): string | undefined {
  const here = dirname(fileURLToPath(import.meta.url));
  for (const p of [join(here, '..', 'gitleaks.toml'), join(here, '..', '..', 'gitleaks.toml')]) {
    if (existsSync(p)) return p;
  }
  return undefined;
}

export async function runGitleaks(request: ScanRequest): Promise<ScanOutcome> {
  // Materialize request files into an isolated temp dir (path-traversal safe).
  const mat = materializeFiles(request.files, 'safeweave-secrets-');

  try {
    return await executeGitleaks(mat.dir);
  } finally {
    mat.cleanup();
  }
}

function executeGitleaks(targetDir: string): Promise<ScanOutcome> {
  const reportPath = join(targetDir, 'gitleaks-report.json');

  const configPath = resolveConfigPath();
  const args = ['detect', '--source', targetDir, '--report-format', 'json', '--report-path', reportPath, '--no-git', '--exit-code', '0'];
  if (configPath) args.push('--config', configPath);

  return new Promise((resolve) => {
    execFile(
      'gitleaks',
      args,
      { timeout: 60000 },
      (error) => {
        // ENOENT means the binary is absent; anything else means it ran and
        // failed. Both used to end as an empty findings array, i.e. "no secrets
        // found" — the most dangerous false negative this product can emit.
        if (error) {
          const missing = (error as NodeJS.ErrnoException).code === 'ENOENT';
          resolve({
            findings: [],
            warnings: [missing
              ? engineUnavailable('Gitleaks (secret scanning)', 'Install it (https://github.com/gitleaks/gitleaks) or use the SafeWeave container image.')
              : `Gitleaks failed to complete, so secret-scanning results are INCOMPLETE: ${error.message}`],
          });
          return;
        }

        try {
          const raw = readFileSync(reportPath, 'utf-8');
          const report = JSON.parse(raw);
          const findings: Finding[] = (report || []).map((leak: Record<string, unknown>) => ({
            id: `SECRET-${(leak.RuleID as string) || 'unknown'}`,
            severity: 'critical' as const,
            title: `Secret detected: ${leak.Description || leak.RuleID}`,
            description: `A secret or credential was found in the code: ${leak.Match || ''}`,
            file: ((leak.File as string) || '').replace(targetDir + '/', ''),
            line: leak.StartLine as number,
            cwe: 'CWE-798',
            remediation: 'Remove the secret from source code. Use environment variables or a secrets manager instead.',
          }));
          resolve({ findings, warnings: [] });
        } catch {
          resolve({
            findings: [],
            warnings: ['Gitleaks produced no readable report, so secret-scanning results are INCOMPLETE.'],
          });
        }
      }
    );
  });
}
