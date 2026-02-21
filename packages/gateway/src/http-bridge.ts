import { createServer as createHttpServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { loadConfig } from './config.js';
import { Router } from './router/index.js';
import { ProfileManager } from './profiles/index.js';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import { createServer as createMcpServer } from './server.js';

const MAX_BODY_SIZE = 5 * 1024 * 1024; // 5 MB

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let totalSize = 0;
    req.on('data', (chunk: Buffer) => {
      totalSize += chunk.length;
      if (totalSize > MAX_BODY_SIZE) {
        req.destroy();
        reject(new Error('Request body too large'));
        return;
      }
      chunks.push(chunk);
    });
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

  // Track SSE transports by session ID
  const sseTransports = new Map<string, SSEServerTransport>();

  const httpServer = createHttpServer(async (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    try {
      // --- MCP SSE endpoints ---

      // GET /sse — establish SSE stream
      if (req.method === 'GET' && (req.url === '/sse' || req.url === '/mcp')) {
        const transport = new SSEServerTransport('/messages', res);
        sseTransports.set(transport.sessionId, transport);

        transport.onclose = () => {
          sseTransports.delete(transport.sessionId);
        };

        const mcpServer = createMcpServer(projectDir);
        // connect() calls transport.start() internally — do not call start() again
        await mcpServer.connect(transport);
        return;
      }

      // POST /messages?sessionId=xxx — client sends MCP messages
      if (req.method === 'POST' && req.url?.startsWith('/messages')) {
        const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
        const sessionId = url.searchParams.get('sessionId');

        if (!sessionId || !sseTransports.has(sessionId)) {
          sendJson(res, 400, { error: 'Invalid or missing sessionId' });
          return;
        }

        const transport = sseTransports.get(sessionId)!;
        await transport.handlePostMessage(req, res);
        return;
      }

      // --- REST API endpoints ---

      if (req.method === 'GET' && req.url === '/api/health') {
        const health = await router.healthCheck();
        sendJson(res, 200, { status: 'ok', scanners: health });
        return;
      }

      if (req.method === 'POST' && req.url === '/api/scan') {
        let rawBody: string;
        try {
          rawBody = await readBody(req);
        } catch (err) {
          sendJson(res, 413, { error: 'Request body too large' });
          return;
        }

        let body: { directory?: string; files?: string[]; scanners?: string[]; target_url?: string };
        try {
          body = JSON.parse(rawBody);
        } catch {
          sendJson(res, 400, { error: 'Invalid JSON in request body' });
          return;
        }

        if (body && typeof body !== 'object') {
          sendJson(res, 400, { error: 'Request body must be a JSON object' });
          return;
        }

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
      if (!res.headersSent) {
        sendJson(res, 500, { error: 'Internal server error' });
      }
    }
  });

  httpServer.listen(port, host, () => {
    console.log(`SafeWeave HTTP bridge listening on http://${host}:${port}`);
    console.log(`MCP SSE endpoint available at http://${host}:${port}/sse`);
  });
}
