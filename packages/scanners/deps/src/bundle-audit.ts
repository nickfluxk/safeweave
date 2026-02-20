import { execFile } from 'node:child_process';
import type { Finding } from '@safeweave/common';
import type { EcosystemAuditor } from './types.js';

function mapGemSeverity(criticality: string | undefined): Finding['severity'] {
  switch (criticality?.toLowerCase()) {
    case 'critical': return 'critical';
    case 'high': return 'high';
    case 'medium': return 'medium';
    case 'low': return 'low';
    default: return 'medium';
  }
}

export const bundleAuditor: EcosystemAuditor = {
  prefix: 'GEM',
  ecosystem: 'ruby',
  indicators: ['Gemfile.lock', 'Gemfile'],
  manifestFile: 'Gemfile',

  audit(rootDir: string): Promise<Finding[]> {
    return new Promise((resolve) => {
      execFile(
        'bundle-audit',
        ['check', '--format=json'],
        { cwd: rootDir, timeout: 120_000 },
        (_error, stdout) => {
          if (!stdout) {
            resolve([]);
            return;
          }

          try {
            const output = JSON.parse(stdout);
            const results = output.results || [];

            const findings: Finding[] = results.map(
              (v: {
                advisory: {
                  id?: string;
                  cve?: string;
                  title?: string;
                  criticality?: string;
                  patched_versions?: string[];
                };
                gem: { name: string; version: string };
              }) => {
                const advisoryId = v.advisory.cve || v.advisory.id || 'unknown';
                return {
                  id: `DEP-GEM-${advisoryId}`,
                  severity: mapGemSeverity(v.advisory.criticality),
                  title: `Vulnerable dependency: ${v.gem.name}@${v.gem.version}`,
                  description: v.advisory.title || `${advisoryId} in ${v.gem.name}@${v.gem.version}`,
                  file: 'Gemfile',
                  remediation: v.advisory.patched_versions?.length
                    ? `Upgrade ${v.gem.name} to ${v.advisory.patched_versions[0]}`
                    : `Replace or remove ${v.gem.name}`,
                  cwe: undefined,
                };
              },
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
