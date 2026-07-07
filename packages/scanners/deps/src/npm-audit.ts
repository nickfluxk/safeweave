import { execFile } from 'node:child_process';
import type { Finding } from '@safeweave/common';
import type { EcosystemAuditor } from './types.js';

function mapNpmSeverity(severity: string | undefined): Finding['severity'] {
  switch (severity) {
    case 'critical': return 'critical';
    case 'high': return 'high';
    case 'moderate': return 'medium';
    case 'low': return 'low';
    default: return 'info';
  }
}

export const npmAuditor: EcosystemAuditor = {
  prefix: 'NPM',
  ecosystem: 'npm',
  indicators: ['package-lock.json', 'package.json'],
  manifestFile: 'package.json',

  audit(rootDir: string): Promise<Finding[]> {
    return new Promise((resolve) => {
      execFile('npm', ['audit', '--json'], { cwd: rootDir, timeout: 60_000 }, (_error, stdout) => {
        if (!stdout) {
          resolve([]);
          return;
        }

        try {
          const output = JSON.parse(stdout);
          const findings: Finding[] = [];

          const vulnerabilities = output.vulnerabilities || {};
          for (const [name, vuln] of Object.entries(vulnerabilities)) {
            const v = vuln as Record<string, unknown>;
            findings.push({
              id: `DEP-NPM-${name}`,
              severity: mapNpmSeverity(v.severity as string),
              title: `Vulnerable dependency: ${name}`,
              description: (v.via as Array<Record<string, string>>)?.[0]?.title || `Known vulnerability in ${name}`,
              file: 'package.json',
              remediation: v.fixAvailable ? 'Run: npm audit fix' : 'Update or replace this dependency',
              cwe: (v.via as Array<Record<string, string>>)?.[0]?.cwe?.[0],
            });
          }

          resolve(findings);
        } catch {
          resolve([]);
        }
      });
    });
  },
};
