import { execFile } from 'node:child_process';
import { engineUnavailable, type ScanRequest, type Finding, type ScanOutcome } from '@safeweave/common';

function mapNucleiSeverity(severity: string): Finding['severity'] {
  switch (severity?.toLowerCase()) {
    case 'critical': return 'critical';
    case 'high': return 'high';
    case 'medium': return 'medium';
    case 'low': return 'low';
    default: return 'info';
  }
}

/**
 * Reject targets that point at loopback / link-local / private network ranges
 * so DAST can't be used as an SSRF tool against internal services.
 */
export function isUnsafeTarget(rawUrl: string): boolean {
  let host: string;
  try {
    host = new URL(rawUrl).hostname.toLowerCase();
  } catch {
    return true;
  }

  // URL.hostname returns IPv6 literals WRAPPED IN BRACKETS ('[::1]'), so every
  // bare-literal comparison below silently missed them and `http://[::1]:9001/`
  // sailed through as a safe target — turning this service into an SSRF probe
  // against the scanner host's own loopback interface.
  if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1);

  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.internal') || host.endsWith('.local')) {
    return true;
  }

  if (host === '::1' || host === '::' || host === '0.0.0.0') return true;

  // IPv6 unique-local (fc00::/7) and link-local (fe80::/10) — the v6 analogues
  // of 10.0.0.0/8 and 169.254.0.0/16, and the usual route to cloud metadata.
  if (/^f[cd][0-9a-f]{0,2}:/.test(host)) return true;
  if (/^fe[89ab][0-9a-f]?:/.test(host)) return true;

  // IPv4-mapped IPv6 reaches the same interfaces as the bare IPv4 address, so
  // evaluate the embedded v4 address under the v4 rules below.
  //
  // Note WHRWG URL normalizes '::ffff:127.0.0.1' to the hex form
  // '::ffff:7f00:1', so matching a dotted quad alone silently missed it — which
  // is how ::ffff:169.254.169.254 (cloud metadata) would have slipped past.
  let candidate = host;
  const mappedHex = host.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
  if (mappedHex) {
    const hi = parseInt(mappedHex[1], 16);
    const lo = parseInt(mappedHex[2], 16);
    candidate = [hi >> 8, hi & 0xff, lo >> 8, lo & 0xff].join('.');
  } else {
    const mappedDotted = host.match(/^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
    if (mappedDotted) candidate = mappedDotted[1];
  }

  const m = candidate.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) {
    const [a, b] = [Number(m[1]), Number(m[2])];
    if (a === 127 || a === 10 || a === 0) return true;
    if (a === 169 && b === 254) return true;
    if (a === 192 && b === 168) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
  }
  return false;
}

export function runNuclei(request: ScanRequest): Promise<ScanOutcome> {
  const targetUrl = request.context.target_url;
  if (!targetUrl) {
    return Promise.resolve({ findings: [], warnings: ['No target_url provided, so no DAST scan ran.'] });
  }
  // Say so out loud. Returning an empty findings array made a REFUSED target
  // look identical to a clean one.
  if (isUnsafeTarget(targetUrl)) {
    return Promise.resolve({
      findings: [],
      warnings: [`Refused to scan ${targetUrl}: it resolves to a loopback, link-local or private address. No DAST scan ran.`],
    });
  }

  return new Promise((resolve) => {
    execFile('nuclei', ['-u', targetUrl, '-jsonl', '-silent'],
      { timeout: 180_000, maxBuffer: 10 * 1024 * 1024 },
      (error, stdout) => {
        if (!stdout) {
          const missing = (error as NodeJS.ErrnoException | null)?.code === 'ENOENT';
          resolve({
            findings: [],
            warnings: [missing
              ? engineUnavailable('Nuclei (DAST)', 'Install it (https://github.com/projectdiscovery/nuclei) or use the SafeWeave container image.')
              : `Nuclei did not complete, so DAST results are INCOMPLETE${error ? `: ${error.message}` : ''}.`],
          });
          return;
        }
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
          resolve({ findings, warnings: [] });
        } catch {
          resolve({
            findings: [],
            warnings: ['Nuclei output could not be parsed, so DAST results are INCOMPLETE.'],
          });
        }
      });
  });
}
