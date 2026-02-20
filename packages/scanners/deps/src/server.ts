import { createServer as createHttpServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { ScanRequest, ScanResult, Finding } from '@safeweave/common';
import type { EcosystemAuditor } from './types.js';
import { detectEcosystems } from './detect.js';
import { npmAuditor } from './npm-audit.js';
import { pipAuditor } from './pip-audit.js';
import { goAuditor } from './go-audit.js';
import { cargoAuditor } from './cargo-audit.js';
import { bundleAuditor } from './bundle-audit.js';

export const ALL_AUDITORS: EcosystemAuditor[] = [
  npmAuditor,
  pipAuditor,
  goAuditor,
  cargoAuditor,
  bundleAuditor,
];

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
      return json(res, 200, { status: 'healthy', scanner: 'deps', version: '0.1.0' });
    }

    if (req.url === '/scan' && req.method === 'POST') {
      const start = Date.now();
      const body = await readBody(req);
      const request: ScanRequest = JSON.parse(body);
      const rootDir = request.context.rootDir || process.cwd();

      const detected = detectEcosystems(rootDir, ALL_AUDITORS);
      const results = await Promise.allSettled(detected.map((a) => a.audit(rootDir)));

      const findings: Finding[] = [];
      const warnings: string[] = [];

      results.forEach((r, i) => {
        if (r.status === 'fulfilled') {
          findings.push(...r.value);
        } else {
          const auditor = detected[i];
          const reason = r.reason instanceof Error ? r.reason.message : String(r.reason);
          warnings.push(`${auditor.ecosystem} audit failed: ${reason}`);
        }
      });

      const result: ScanResult = {
        findings,
        metadata: {
          scanner: 'deps',
          version: '0.1.0',
          duration_ms: Date.now() - start,
          files_scanned: request.files.length,
          timestamp: new Date().toISOString(),
          ...(warnings.length > 0 ? { warnings } : {}),
        },
      };
      return json(res, 200, result);
    }

    json(res, 404, { error: 'Not found' });
  });
}
