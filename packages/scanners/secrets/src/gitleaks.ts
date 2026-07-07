import { execFile } from 'node:child_process';
import { writeFileSync, mkdtempSync, mkdirSync, rmSync, readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import type { ScanRequest, Finding } from '@safeweave/common';
import { resolveBinary } from '@safeweave/common';

export async function runGitleaks(request: ScanRequest): Promise<Finding[]> {
  const bin = await resolveBinary('gitleaks');
  if (!bin) return [];

  const tempDir = mkdtempSync(join(tmpdir(), 'safeweave-secrets-'));

  try {
    for (const file of request.files) {
      if (file.content) {
        const filePath = join(tempDir, file.path);
        mkdirSync(dirname(filePath), { recursive: true });
        writeFileSync(filePath, file.content);
      }
    }

    return await executeGitleaks(bin, tempDir);
  } finally {
    rmSync(tempDir, { recursive: true, force: true });
  }
}

function executeGitleaks(binaryPath: string, targetDir: string): Promise<Finding[]> {
  const reportPath = join(targetDir, 'gitleaks-report.json');

  return new Promise((resolve) => {
    execFile(
      binaryPath,
      ['detect', '--source', targetDir, '--report-format', 'json', '--report-path', reportPath, '--no-git', '--exit-code', '0'],
      { timeout: 60000 },
      (error) => {
        if (error && (error as NodeJS.ErrnoException).code !== 'ENOENT') {
          // Unexpected failure
          resolve([]);
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
          resolve(findings);
        } catch {
          resolve([]);
        }
      }
    );
  });
}
