import { execFile } from 'node:child_process';
import { engineUnavailable, materializeFiles, type ScanRequest, type Finding, type ScanOutcome } from '@safeweave/common';

function mapTrivySeverity(severity: string): Finding['severity'] {
  switch (severity?.toUpperCase()) {
    case 'CRITICAL': return 'critical';
    case 'HIGH': return 'high';
    case 'MEDIUM': return 'medium';
    case 'LOW': return 'low';
    default: return 'info';
  }
}

export async function runTrivyVuln(request: ScanRequest): Promise<ScanOutcome> {
  // Scan the files sent in the request (works across hosts); fall back to
  // context.rootDir only when no file content was provided.
  const hasContent = (request.files || []).some((f) => f.content != null);
  const mat = hasContent ? materializeFiles(request.files, 'safeweave-container-') : null;
  const rootDir = mat ? mat.dir : (request.context.rootDir || process.cwd());

  try {
    return await new Promise<ScanOutcome>((resolve) => {
      execFile('trivy', ['fs', '--scanners', 'vuln', '--format', 'json', rootDir],
        { timeout: 120_000, maxBuffer: 10 * 1024 * 1024 },
        (error, stdout) => {
          // No stdout means Trivy never produced a report — usually a missing
          // binary. Reporting that as zero findings read as a clean scan.
          if (!stdout) {
            const missing = (error as NodeJS.ErrnoException | null)?.code === 'ENOENT';
            resolve({
              findings: [],
              warnings: [missing
                ? engineUnavailable('Trivy (container)', 'Install Trivy (https://trivy.dev) or use the SafeWeave container image.')
                : `Trivy did not complete, so container vulnerability results are INCOMPLETE${error ? `: ${error.message}` : ''}.`],
            });
            return;
          }
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
            resolve({ findings, warnings: [] });
          } catch {
            resolve({
              findings: [],
              warnings: ['Trivy output could not be parsed, so container vulnerability results are INCOMPLETE.'],
            });
          }
        });
    });
  } finally {
    mat?.cleanup();
  }
}
