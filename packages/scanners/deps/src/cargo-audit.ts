import { execFile } from 'node:child_process';
import type { Finding } from '@safeweave/common';
import type { EcosystemAuditor } from './types.js';

function mapCargoSeverity(cvss: number | undefined): Finding['severity'] {
  if (cvss === undefined) return 'medium';
  if (cvss >= 9.0) return 'critical';
  if (cvss >= 7.0) return 'high';
  if (cvss >= 4.0) return 'medium';
  if (cvss > 0) return 'low';
  return 'info';
}

export const cargoAuditor: EcosystemAuditor = {
  prefix: 'CARGO',
  ecosystem: 'rust',
  indicators: ['Cargo.lock', 'Cargo.toml'],
  manifestFile: 'Cargo.toml',

  audit(rootDir: string): Promise<Finding[]> {
    return new Promise((resolve) => {
      execFile(
        'cargo',
        ['audit', '--json'],
        { cwd: rootDir, timeout: 120_000 },
        (_error, stdout) => {
          if (!stdout) {
            resolve([]);
            return;
          }

          try {
            const output = JSON.parse(stdout);
            const vulnerabilities = output.vulnerabilities?.list || [];

            const findings: Finding[] = vulnerabilities.map(
              (v: {
                advisory: {
                  id: string;
                  title?: string;
                  description?: string;
                  cvss?: number;
                  package: string;
                  patched_versions?: string[];
                };
              }) => ({
                id: `DEP-CARGO-${v.advisory.id}`,
                severity: mapCargoSeverity(v.advisory.cvss),
                title: `Vulnerable dependency: ${v.advisory.package}`,
                description: v.advisory.title || v.advisory.description || `${v.advisory.id} in ${v.advisory.package}`,
                file: 'Cargo.toml',
                remediation: v.advisory.patched_versions?.length
                  ? `Upgrade ${v.advisory.package} to ${v.advisory.patched_versions[0]}`
                  : `Replace or remove ${v.advisory.package}`,
                cwe: undefined,
              }),
            );

            resolve(findings);
          } catch {
            resolve([]);
          }
        },
      );
    });
  },
};
