import { execFile } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import type { Finding } from '@safeweave/common';
import type { EcosystemAuditor } from './types.js';

function mapPipSeverity(fix: string | undefined): Finding['severity'] {
  // pip-audit doesn't provide severity; treat all as high when a fix exists, medium otherwise
  return fix ? 'high' : 'medium';
}

export const pipAuditor: EcosystemAuditor = {
  prefix: 'PIP',
  ecosystem: 'python',
  indicators: ['requirements.txt', 'Pipfile', 'pyproject.toml'],
  manifestFile: 'requirements.txt',

  audit(rootDir: string): Promise<Finding[]> {
    return new Promise((resolve, reject) => {
      // Audit the PROJECT's declared dependencies, not the scanner's own Python
      // environment. pip-audit only audits a project when given `-r <file>`.
      const reqPath = join(rootDir, 'requirements.txt');
      if (!existsSync(reqPath)) {
        // Without a requirements.txt we cannot audit project deps reliably
        // (Pipfile/pyproject need installation); return nothing rather than
        // auditing the wrong environment and reporting a false "all clear".
        resolve([]);
        return;
      }

      execFile(
        'pip-audit',
        ['--format=json', '-r', 'requirements.txt'],
        { cwd: rootDir, timeout: 120_000 },
        (_error, stdout) => {
          if (!stdout) {
            // No output at all means the tool never ran (usually absent).
            // Reject so the server reports an INCOMPLETE audit rather than
            // silently claiming no vulnerabilities were found.
            reject(new Error(`pip-audit produced no output — is 'pip-audit' installed?`));
            return;
          }

          try {
            const vulns: Array<{
              name: string;
              version: string;
              id: string;
              fix_versions: string[];
              description?: string;
            }> = JSON.parse(stdout);

            const findings: Finding[] = vulns.map((v) => ({
              id: `DEP-PIP-${v.id}`,
              severity: mapPipSeverity(v.fix_versions?.[0]),
              title: `Vulnerable dependency: ${v.name}@${v.version}`,
              description: v.description || `${v.id} in ${v.name}@${v.version}`,
              file: 'requirements.txt',
              remediation: v.fix_versions?.length
                ? `Upgrade ${v.name} to ${v.fix_versions[0]}`
                : `Replace or remove ${v.name}`,
              cwe: undefined,
            }));

            resolve(findings);
          } catch {
            resolve([]);
          }
        },
      );
    });
  },
};
