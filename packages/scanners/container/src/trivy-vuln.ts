import { execFile } from 'node:child_process';
import type { Finding, ScanRequest } from '@safeweave/common';
import { resolveBinary } from '@safeweave/common';

function mapTrivySeverity(severity: string): Finding['severity'] {
  switch (severity?.toUpperCase()) {
    case 'CRITICAL': return 'critical';
    case 'HIGH': return 'high';
    case 'MEDIUM': return 'medium';
    case 'LOW': return 'low';
    default: return 'info';
  }
}

export async function runTrivyVuln(request: ScanRequest): Promise<Finding[]> {
  const bin = await resolveBinary('trivy');
  if (!bin) return [];

  const rootDir = request.context.rootDir || process.cwd();
  return executeTrivyVuln(bin, rootDir);
}

function executeTrivyVuln(binaryPath: string, rootDir: string): Promise<Finding[]> {
  return new Promise((resolve) => {
    execFile(binaryPath, ['fs', '--scanners', 'vuln', '--format', 'json', rootDir],
      { timeout: 120_000, maxBuffer: 10 * 1024 * 1024 },
      (_error, stdout) => {
        if (!stdout) { resolve([]); return; }
        try {
          const output = JSON.parse(stdout);
          const findings: Finding[] = [];
          for (const result of output.Results || []) {
            for (const vuln of result.Vulnerabilities || []) {
              findings.push({
                id: `CONTAINER-${vuln.VulnerabilityID}`,
                severity: mapTrivySeverity(vuln.Severity),
                title: `${vuln.VulnerabilityID}: ${vuln.PkgName}@${vuln.InstalledVersion}`,
                description: vuln.Title || vuln.Description || '',
                file: result.Target || '',
                remediation: vuln.FixedVersion
                  ? `Upgrade ${vuln.PkgName} to ${vuln.FixedVersion}`
                  : 'No fix available — consider alternative package',
                cwe: vuln.CweIDs?.[0],
              });
            }
          }
          resolve(findings);
        } catch { resolve([]); }
      });
  });
}
