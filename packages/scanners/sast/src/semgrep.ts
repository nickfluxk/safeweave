import { execFile } from 'node:child_process';
import { materializeFiles } from '@safeweave/common';
import { engineUnavailable, type ScanRequest, type Finding, type ScanOutcome } from '@safeweave/common';

export async function runSemgrep(request: ScanRequest): Promise<ScanOutcome> {
  // Materialize request files into an isolated temp dir (path-traversal safe).
  const mat = materializeFiles(request.files, 'safeweave-sast-');

  try {
    return await executeSemgrep(mat.dir);
  } finally {
    mat.cleanup();
  }
}

function executeSemgrep(targetDir: string): Promise<ScanOutcome> {
  return new Promise((resolve) => {
    const args = [
      '--json',
      '--config', 'auto',
      targetDir,
    ];

    execFile('semgrep', args, { timeout: 60000, maxBuffer: 10 * 1024 * 1024 }, (error, stdout) => {
      if (error && !stdout) {
        // Semgrep missing, timed out, or crashed. Report it — an empty findings
        // array here previously read as "clean" all the way to a grade of A.
        resolve({
          findings: [],
          warnings: [engineUnavailable('Semgrep (SAST)', 'Install it (https://semgrep.dev/docs/getting-started) or use the SafeWeave container image.')],
        });
        return;
      }

      try {
        const output = JSON.parse(stdout);
        const findings: Finding[] = (output.results || []).map((r: Record<string, unknown>) => ({
          id: `SAST-${(r.check_id as string || 'unknown').replace(/\./g, '-')}`,
          severity: mapSemgrepSeverity(r.extra as Record<string, unknown>),
          title: r.check_id as string || 'Unknown',
          description: ((r.extra as Record<string, unknown>)?.message as string) || '',
          file: (r.path as string || '').replace(targetDir + '/', ''),
          line: (r.start as Record<string, number>)?.line,
          cwe: extractCwe(r.extra as Record<string, unknown>),
          remediation: ((r.extra as Record<string, unknown>)?.fix as string) || 'Review and fix the flagged code pattern',
        }));
        resolve({ findings, warnings: [] });
      } catch {
        resolve({
          findings: [],
          warnings: ['Semgrep produced output that could not be parsed, so SAST results are INCOMPLETE.'],
        });
      }
    });
  });
}

function mapSemgrepSeverity(extra: Record<string, unknown> | undefined): Finding['severity'] {
  const sev = (extra?.severity as string || '').toUpperCase();
  switch (sev) {
    case 'ERROR': return 'high';
    case 'WARNING': return 'medium';
    case 'INFO': return 'low';
    default: return 'info';
  }
}

function extractCwe(extra: Record<string, unknown> | undefined): string | undefined {
  const metadata = extra?.metadata as Record<string, unknown> | undefined;
  const cwe = metadata?.cwe as string[] | string | undefined;
  if (Array.isArray(cwe)) return cwe[0];
  if (typeof cwe === 'string') return cwe;
  return undefined;
}
