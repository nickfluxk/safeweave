import { execFile } from 'node:child_process';
import type { Finding, ScanRequest } from '@safeweave/common';

function mapNucleiSeverity(severity: string): Finding['severity'] {
  switch (severity?.toLowerCase()) {
    case 'critical': return 'critical';
    case 'high': return 'high';
    case 'medium': return 'medium';
    case 'low': return 'low';
    default: return 'info';
  }
}

export function runNuclei(request: ScanRequest): Promise<Finding[]> {
  const targetUrl = request.context.target_url;
  if (!targetUrl) return Promise.resolve([]);

  return new Promise((resolve) => {
    execFile('nuclei', ['-u', targetUrl, '-jsonl', '-silent'],
      { timeout: 180_000, maxBuffer: 10 * 1024 * 1024 },
      (_error, stdout) => {
        if (!stdout) { resolve([]); return; }
        try {
          const findings: Finding[] = [];
          for (const line of stdout.split('\n')) {
            if (!line.trim()) continue;
            const entry = JSON.parse(line);
            findings.push({
              id: `DAST-${entry['template-id'] || 'UNKNOWN'}`,
              severity: mapNucleiSeverity(entry.info?.severity),
              title: entry.info?.name || entry['template-id'] || 'DAST finding',
              description: entry.info?.description || `Found at ${entry['matched-at'] || targetUrl}`,
              file: entry['matched-at'] || targetUrl,
              remediation: entry.info?.remediation || 'Review endpoint security configuration',
              cwe: entry.info?.classification?.cwe?.[0],
            });
          }
          resolve(findings);
        } catch { resolve([]); }
      });
  });
}
