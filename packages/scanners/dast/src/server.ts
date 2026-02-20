import { createServer as createHttpServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { runNuclei } from './nuclei.js';
import type { ScanRequest, ScanResult } from '@safeweave/common';

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks).toString()));
    req.on('error', reject);
  });
}

function json(res: ServerResponse, status: number, data: unknown) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

export function createServer() {
  return createHttpServer(async (req, res) => {
    if (req.url === '/health' && req.method === 'GET') {
      return json(res, 200, { status: 'healthy', scanner: 'dast', version: '0.1.0' });
    }

    if (req.url === '/scan' && req.method === 'POST') {
      const start = Date.now();
      try {
        const body = await readBody(req);
        const request: ScanRequest = JSON.parse(body);

        const warnings: string[] = [];
        if (!request.context.target_url) {
          warnings.push('No target_url provided in context — DAST scan requires a target URL');
        }

        const findings = await runNuclei(request);

        const result: ScanResult = {
          findings,
          metadata: {
            scanner: 'dast',
            version: '0.1.0',
            duration_ms: Date.now() - start,
            files_scanned: request.files.length,
            timestamp: new Date().toISOString(),
            warnings: warnings.length > 0 ? warnings : undefined,
          },
        };
        return json(res, 200, result);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        const result: ScanResult = {
          findings: [],
          metadata: {
            scanner: 'dast',
            version: '0.1.0',
            duration_ms: Date.now() - start,
            files_scanned: 0,
            timestamp: new Date().toISOString(),
            warnings: [`DAST scan failed: ${message}`],
          },
        };
        return json(res, 200, result);
      }
    }

    json(res, 404, { error: 'Not found' });
  });
}
