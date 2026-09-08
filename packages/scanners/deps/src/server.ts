import { createServer as createHttpServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { ScanRequest, ScanResult, Finding } from '@safeweave/common';
import { materializeFiles } from '@safeweave/common';
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
      return json(res, 200, { status: 'healthy', scanner: 'deps', version: '0.1.0' });
    }

    if (req.url === '/scan' && req.method === 'POST') {
      const start = Date.now();
      let body: string;
      try {
        body = await readBody(req);
      } catch (err) {
        if ((err as { statusCode?: number })?.statusCode === 413) {
          return json(res, 413, { error: 'Request body too large' });
        }
        // Was `throw err` — inside an async createHttpServer handler nothing
        // catches that, and Node terminates the process on the unhandled
        // rejection. The client got no response and the whole dependency-audit
        // service stayed down until the container restarted.
        const message = err instanceof Error ? err.message : String(err);
        return json(res, 400, { error: `Could not read request body: ${message}` });
      }

      let request: ScanRequest;
      try {
        request = JSON.parse(body) as ScanRequest;
      } catch {
        // Same reason: an unguarded JSON.parse on attacker-controlled input was
        // a one-request denial of service against this scanner.
        return json(res, 400, { error: 'Request body is not valid JSON' });
      }

      // Prefer the files sent in the request (works across hosts in distributed
      // deployments). Fall back to context.rootDir only when no content is sent.
      const hasContent = (request.files || []).some((f) => f.content != null);
      const mat = hasContent ? materializeFiles(request.files, 'safeweave-deps-') : null;
      const rootDir = mat ? mat.dir : (request.context.rootDir || process.cwd());

      const findings: Finding[] = [];
      const warnings: string[] = [];
      if (mat?.skipped.length) {
        warnings.push(`Skipped ${mat.skipped.length} file(s) with unsafe paths`);
      }

      try {
        const detected = detectEcosystems(rootDir, ALL_AUDITORS);
        const results = await Promise.allSettled(detected.map((a) => a.audit(rootDir)));

        results.forEach((r, i) => {
          if (r.status === 'fulfilled') {
            findings.push(...r.value);
          } else {
            const auditor = detected[i];
            const reason = r.reason instanceof Error ? r.reason.message : String(r.reason);
            warnings.push(`${auditor.ecosystem} audit failed: ${reason}`);
          }
        });
      } finally {
        mat?.cleanup();
      }

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
