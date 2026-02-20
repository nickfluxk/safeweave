import { createServer as createHttpServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { loadConfig } from './config.js';
import { Router } from './router/index.js';
import { ProfileManager } from './profiles/index.js';

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf-8')));
    req.on('error', reject);
  });
}

function sendJson(res: ServerResponse, status: number, data: unknown) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(body),
  });
  res.end(body);
}

export function startHttpBridge(projectDir: string): void {
  const config = loadConfig(projectDir);
  const router = new Router(config);
  const profileManager = new ProfileManager();

  const host = config.gateway.host;
  const port = config.gateway.port;

  const server = createHttpServer(async (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    try {
      if (req.method === 'GET' && req.url === '/api/health') {
        const health = await router.healthCheck();
        sendJson(res, 200, { status: 'ok', scanners: health });
        return;
      }

      if (req.method === 'POST' && req.url === '/api/scan') {
        const rawBody = await readBody(req);
        const body = JSON.parse(rawBody) as {
          directory?: string;
          files?: string[];
          scanners?: string[];
          target_url?: string;
        };

        const dir = body.directory || projectDir;
        const profile = profileManager.getActive();

        let requestedScanners: Set<string> | undefined;
        if (body.scanners && body.scanners.length > 0) {
          requestedScanners = new Set(body.scanners);
        }

        const files = body.files
          ? body.files.map((f) => ({ path: f }))
          : [{ path: dir }];

        const result = await router.scanAll(
          {
            files,
            profile: { name: profile.name, rules: profile.rules as Record<string, unknown> },
            context: { rootDir: dir, target_url: body.target_url },
          },
          requestedScanners,
        );

        sendJson(res, 200, result);
        return;
      }

      sendJson(res, 404, { error: 'Not found' });
    } catch (err) {
      console.error('HTTP bridge error:', err);
      sendJson(res, 500, { error: 'Internal server error' });
    }
  });

  server.listen(port, host, () => {
    console.log(`SafeWeave HTTP bridge listening on http://${host}:${port}`);
  });
}
