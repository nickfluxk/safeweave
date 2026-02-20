import { execFile } from 'node:child_process';
import type { Finding } from '@safeweave/common';
import type { EcosystemAuditor } from './types.js';

function mapGoSeverity(severity: string | undefined): Finding['severity'] {
  switch (severity?.toUpperCase()) {
    case 'CRITICAL': return 'critical';
    case 'HIGH': return 'high';
    case 'MEDIUM': return 'medium';
    case 'LOW': return 'low';
    default: return 'medium';
  }
}

interface GoVuln {
  osv: {
    id: string;
    summary?: string;
    details?: string;
    database_specific?: { severity?: string };
    affected?: Array<{ package?: { name?: string } }>;
  };
}

/** Parse govulncheck NDJSON output into vulnerability entries. */
export function parseGovulncheckOutput(stdout: string): GoVuln[] {
  const vulns: GoVuln[] = [];
  for (const line of stdout.split('\n')) {
    if (!line.trim()) continue;
    try {
      const entry = JSON.parse(line);
      if (entry.osv) {
        vulns.push(entry as GoVuln);
      }
    } catch {
      // skip malformed lines
    }
  }
  return vulns;
}

export const goAuditor: EcosystemAuditor = {
  prefix: 'GO',
  ecosystem: 'go',
  indicators: ['go.sum', 'go.mod'],
  manifestFile: 'go.mod',

  audit(rootDir: string): Promise<Finding[]> {
    return new Promise((resolve) => {
      execFile(
        'govulncheck',
        ['-json', './...'],
        { cwd: rootDir, timeout: 120_000 },
        (_error, stdout) => {
          if (!stdout) {
            resolve([]);
            return;
          }

          try {
            const vulns = parseGovulncheckOutput(stdout);
            const findings: Finding[] = vulns.map((v) => {
              const pkg = v.osv.affected?.[0]?.package?.name || 'unknown';
              return {
                id: `DEP-GO-${v.osv.id}`,
                severity: mapGoSeverity(v.osv.database_specific?.severity),
                title: `Vulnerable dependency: ${pkg}`,
                description: v.osv.summary || v.osv.details || `${v.osv.id} in ${pkg}`,
                file: 'go.mod',
                remediation: `Run: go get -u ${pkg}`,
                cwe: undefined,
              };
            });

            resolve(findings);
          } catch {
            resolve([]);
          }
        },
      );
    });
  },
};
