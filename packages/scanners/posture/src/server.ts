import { createServer as createHttpServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { runPostureChecks } from './checks.js';
import type { ScanRequest, ScanResult } from '@safeweave/common';
import { validateScanRequest } from '@safeweave/common';

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let totalSize = 0;
    req.on('data', (chunk: Buffer) => {
      totalSize += chunk.length;
      if (totalSize > 5 * 1024 * 1024) {
        req.destroy();
        reject(new Error('Request body too large'));
        return;
      }
      chunks.push(chunk);
    });
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
      return json(res, 200, { status: 'healthy', scanner: 'posture', version: '0.1.0' });
    }

    if (req.url === '/scan' && req.method === 'POST') {
      const start = Date.now();
      try {
        const body = await readBody(req);
        const request: ScanRequest = JSON.parse(body);
        const validation = validateScanRequest(request);
        if (!validation.valid) {
          return json(res, 400, { error: 'Invalid scan request', details: validation.errors });
        }
        const findings = await runPostureChecks(request);

        const result: ScanResult = {
          findings,
          metadata: {
            scanner: 'posture',
            version: '0.1.0',
            duration_ms: Date.now() - start,
            files_scanned: request.files.length,
            timestamp: new Date().toISOString(),
          },
        };
        return json(res, 200, result);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        const result: ScanResult = {
          findings: [],
          metadata: {
            scanner: 'posture',
            version: '0.1.0',
            duration_ms: Date.now() - start,
            files_scanned: 0,
            timestamp: new Date().toISOString(),
            warnings: [`API posture scan failed: ${message}`],
          },
        };
        return json(res, 200, result);
      }
    }

    json(res, 404, { error: 'Not found' });
  });
}
