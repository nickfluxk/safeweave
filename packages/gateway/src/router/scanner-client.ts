import type { ScanRequest, ScanResult } from '@safeweave/common';

export class ScannerClient {
  constructor(
    private baseUrl: string,
    public readonly name: string = 'unknown',
  ) {}

  async scan(request: ScanRequest): Promise<ScanResult> {
    try {
      const response = await fetch(`${this.baseUrl}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(request),
      });

      if (!response.ok) {
        throw new Error(`Scanner ${this.name} returned ${response.status}`);
      }

      return await response.json() as ScanResult;
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        findings: [],
        metadata: {
          scanner: this.name,
          version: '0.0.0',
          duration_ms: 0,
          files_scanned: 0,
          timestamp: new Date().toISOString(),
          warnings: [`Scanner '${this.name}' unavailable: ${message}`],
        },
      };
    }
  }

  async isHealthy(): Promise<boolean> {
    try {
      const response = await fetch(`${this.baseUrl}/health`);
      return response.ok;
    } catch {
      return false;
    }
  }
}
