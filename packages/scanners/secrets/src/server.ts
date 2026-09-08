import { createServer as createHttpServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { runGitleaks } from './gitleaks.js';
import type { ScanRequest, ScanResult } from '@safeweave/common';

const MAX_BODY_SIZE = 10 * 1024 * 1024; // 10MB

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let totalSize = 0;
    req.on('data', (chunk: Buffer) => {
      totalSize += chunk.length;
      if (totalSize > MAX_BODY_SIZE) {
        req.destroy();
        const err = new Error('Request body too large') as Error & { statusCode?: number };
        err.statusCode = 413;
        reject(err);
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
      return json(res, 200, { status: 'healthy', scanner: 'secrets', version: '0.1.0' });
    }

    if (req.url === '/scan' && req.method === 'POST') {
      const start = Date.now();
      try {
        const body = await readBody(req);
        const request: ScanRequest = JSON.parse(body);
        const { findings, warnings } = await runGitleaks(request);

        const result: ScanResult = {
          findings,
          metadata: {
            scanner: 'secrets',
            version: '0.1.0',
            duration_ms: Date.now() - start,
            files_scanned: request.files.length,
            timestamp: new Date().toISOString(),
            // An engine that could not run reports it here. Without this a
            // failed scan was indistinguishable from a clean one.
            ...(warnings.length > 0 ? { warnings } : {}),
          },
        };
        return json(res, 200, result);
      } catch (err) {
        if ((err as { statusCode?: number })?.statusCode === 413) {
          return json(res, 413, { error: 'Request body too large' });
        }
        const message = err instanceof Error ? err.message : String(err);
        const result: ScanResult = {
          findings: [],
          metadata: {
            scanner: 'secrets',
            version: '0.1.0',
            duration_ms: Date.now() - start,
            files_scanned: 0,
            timestamp: new Date().toISOString(),
            warnings: [`Secrets scan failed: ${message}`],
          },
        };
        return json(res, 200, result);
      }
    }

    json(res, 404, { error: 'Not found' });
  });
}
