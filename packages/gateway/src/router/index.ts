import type { ScanRequest, ScanResult, Finding } from '@safeweave/common';
import type { SafeweaveConfig } from '../config.js';
import { ScannerClient } from './scanner-client.js';

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
    const promises = Array.from(this.clients.entries())
      .filter(([name]) => !requestedScanners || requestedScanners.has(name))
      .map(async ([_name, client]) => {
        const result = await client.scan(request);
        return { result };
      });

    const results = await Promise.allSettled(promises);
    const allFindings: Finding[] = [];
    const allWarnings: string[] = [];

    for (const result of results) {
      if (result.status === 'fulfilled') {
        allFindings.push(...result.value.result.findings);
        if (result.value.result.metadata.warnings) {
          allWarnings.push(...result.value.result.metadata.warnings);
        }
      }
    }

    return {
      findings: deduplicateFindings(allFindings),
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
