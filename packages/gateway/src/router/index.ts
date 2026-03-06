import type { ScanRequest, ScanResult, Finding, ScannerStatus, Severity } from '@safeweave/common';
import type { SafeweaveConfig } from '../config.js';
import { ScannerClient } from './scanner-client.js';

const ALL_SCANNERS = ['sast', 'secrets', 'deps', 'iac', 'container', 'dast', 'license', 'posture'];

function countSeverities(findings: Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) {
    counts[f.severity] = (counts[f.severity] || 0) + 1;
  }
  return counts;
}

export class Router {
  private clients: Map<string, ScannerClient> = new Map();

  constructor(config: SafeweaveConfig) {
    for (const [name, scanner] of Object.entries(config.scanners)) {
      if (scanner.enabled) {
        this.clients.set(name, new ScannerClient(`http://${scanner.host}:${scanner.port}`, name));
      }
    }
  }

  async scanAll(request: ScanRequest, requestedScanners?: Set<string>): Promise<ScanResult> {
    const start = Date.now();
    const scannersToRun = Array.from(this.clients.entries())
      .filter(([name]) => !requestedScanners || requestedScanners.has(name));

    const promises = scannersToRun.map(async ([name, client]) => {
      const scanStart = Date.now();
      const result = await client.scan(request);
      return { name, result, duration: Date.now() - scanStart };
    });

    const settled = await Promise.allSettled(promises);
    const allFindings: Finding[] = [];
    const allWarnings: string[] = [];
    const scannerResults: ScannerStatus[] = [];

    // Track which scanners actually ran
    const ranScanners = new Set<string>();

    for (const outcome of settled) {
      if (outcome.status === 'fulfilled') {
        const { name, result, duration } = outcome.value;
        ranScanners.add(name);
        allFindings.push(...result.findings);
        if (result.metadata.warnings) {
          allWarnings.push(...result.metadata.warnings);
        }
        scannerResults.push({
          scanner: name,
          status: 'completed',
          findings_count: result.findings.length,
          severity_counts: countSeverities(result.findings),
          duration_ms: duration,
        });
      } else {
        // Promise rejected — shouldn't happen since ScannerClient catches errors,
        // but handle it for safety
        const name = scannersToRun[settled.indexOf(outcome)]?.[0] || 'unknown';
        ranScanners.add(name);
        scannerResults.push({
          scanner: name,
          status: 'error',
          findings_count: 0,
          severity_counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
          duration_ms: 0,
          reason: outcome.reason?.message || 'Unknown error',
        });
      }
    }

    // Add entries for scanners that didn't run (disabled or not requested)
    for (const name of ALL_SCANNERS) {
      if (!ranScanners.has(name)) {
        let reason: string;
        if (requestedScanners && !requestedScanners.has(name)) {
          reason = 'Not requested for this scan';
        } else if (!this.clients.has(name)) {
          reason = 'Scanner not enabled — upgrade plan or check configuration';
        } else {
          reason = 'Skipped';
        }
        scannerResults.push({
          scanner: name,
          status: 'skipped',
          findings_count: 0,
          severity_counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
          duration_ms: 0,
          reason,
        });
      }
    }

    // Sort: completed first, then skipped/error, alphabetically within each group
    const statusOrder = { completed: 0, error: 1, skipped: 2 };
    scannerResults.sort((a, b) => statusOrder[a.status] - statusOrder[b.status] || a.scanner.localeCompare(b.scanner));

    return {
      findings: deduplicateFindings(allFindings),
      scanner_results: scannerResults,
      metadata: {
        scanner: 'safeweave-gateway',
        version: '0.1.0',
        duration_ms: Date.now() - start,
        files_scanned: request.files.length,
        timestamp: new Date().toISOString(),
        ...(allWarnings.length > 0 ? { warnings: allWarnings } : {}),
      },
    };
  }

  async scanWith(scannerName: string, request: ScanRequest): Promise<ScanResult> {
    const client = this.clients.get(scannerName);
    if (!client) {
      return {
        findings: [],
        metadata: {
          scanner: scannerName,
          version: '0.0.0',
          duration_ms: 0,
          files_scanned: 0,
          timestamp: new Date().toISOString(),
        },
      };
    }
    return client.scan(request);
  }

  async healthCheck(): Promise<Record<string, boolean>> {
    const checks: Record<string, boolean> = {};
    for (const [name, client] of this.clients) {
      checks[name] = await client.isHealthy();
    }
    return checks;
  }
}

function deduplicateFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  return findings.filter((f) => {
    const key = `${f.file}:${f.line}:${f.cwe || f.title}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
