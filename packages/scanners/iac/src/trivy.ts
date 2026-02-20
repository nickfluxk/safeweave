import { execFile } from 'node:child_process';
import type { Finding, ScanRequest } from '@safeweave/common';

function mapTrivySeverity(severity: string): Finding['severity'] {
  switch (severity?.toUpperCase()) {
    case 'CRITICAL': return 'critical';
    case 'HIGH': return 'high';
    case 'MEDIUM': return 'medium';
    case 'LOW': return 'low';
    default: return 'info';
  }
}

export function runTrivyMisconfig(request: ScanRequest): Promise<Finding[]> {
  const rootDir = request.context.rootDir || process.cwd();
  return new Promise((resolve) => {
    execFile('trivy', ['fs', '--scanners', 'misconfig', '--format', 'json', rootDir],
      { timeout: 120_000, maxBuffer: 10 * 1024 * 1024 },
      (_error, stdout) => {
        if (!stdout) { resolve([]); return; }
        try {
          const output = JSON.parse(stdout);
          const findings: Finding[] = [];
          for (const result of output.Results || []) {
            for (const vuln of result.Misconfigurations || []) {
              findings.push({
                id: `IAC-${vuln.ID || vuln.AVDID || 'UNKNOWN'}`,
                severity: mapTrivySeverity(vuln.Severity),
                title: vuln.Title || `IaC misconfiguration in ${result.Target}`,
                description: vuln.Description || vuln.Message || '',
                file: result.Target || '',
                remediation: vuln.Resolution || 'Review IaC configuration',
              });
            }
          }
          resolve(findings);
        } catch { resolve([]); }
      });
  });
}
