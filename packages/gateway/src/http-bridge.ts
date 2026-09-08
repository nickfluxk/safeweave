import { createServer as createHttpServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { createHash, timingSafeEqual } from 'node:crypto';
import { readFileSync, existsSync } from 'node:fs';
import { basename } from 'node:path';
import { normalizeRepoSlug, type Finding, type ScanResult } from '@safeweave/common';
import { collectLocalFiles, materializeFiles } from './collect-files.js';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { loadConfig } from './config.js';
import { Router } from './router/index.js';
import { ProfileManager } from './profiles/index.js';
import { LicenseClient } from './license.js';
import { createServer as createMcpServer } from './server.js';

const GATED_SCANNERS = new Set(['iac', 'container', 'dast', 'license', 'posture']);
const LICENSE_SERVER_URL = process.env.SAFEWEAVE_LICENSE_URL || 'https://license.safeweave.dev';

/** Scanners whose target is a URL, so they need no files to be supplied. */
const URL_ONLY_SCANNERS = new Set(['dast']);

/**
 * Accept every documented `files` shape and return one array of {path, content}.
 * Bare path strings are NOT content — they ask the server to read its own disk —
 * so they are excluded here and handled by the access gate instead.
 *
 *   [{ path, content }]        — what the CLI and MCP clients send
 *   { "app.js": "..." }        — the object map shown in the public API docs
 *   ["a.ts", "b.ts"]           — legacy server-side paths (not content)
 */
function normalizeClientFiles(files: unknown): Array<{ path: string; content: string }> {
  if (Array.isArray(files)) {
    return files.filter(
      (f): f is { path: string; content: string } =>
        !!f && typeof f === 'object' && typeof (f as { path?: unknown }).path === 'string'
          && typeof (f as { content?: unknown }).content === 'string',
    );
  }
  if (files && typeof files === 'object') {
    return Object.entries(files as Record<string, unknown>)
      .filter(([path, content]) => path && typeof content === 'string')
      .map(([path, content]) => ({ path, content: content as string }));
  }
  return [];
}

const SCANNER_LABELS: Record<string, string> = {
  iac: 'IaC scanning',
  container: 'container scanning',
  dast: 'DAST scanning',
  license: 'license compliance',
  posture: 'security posture',
};

function upgradeFindings(blockedScanners: string[]): Finding[] {
  return blockedScanners.map((s) => ({
    id: `LICENSE-UPGRADE-${s.toUpperCase()}`,
    severity: 'info' as const,
    title: `Upgrade to Self-Hosted Pro to unlock ${SCANNER_LABELS[s] || s}`,
    description: `${SCANNER_LABELS[s] || s} requires a SafeWeave Self-Hosted Pro license.`,
    file: '',
    remediation: 'Visit https://safeweave.dev/pricing to upgrade',
  }));
}

const MAX_BODY_SIZE = 10 * 1024 * 1024; // 10MB

/** Ceiling on concurrent MCP sessions (each one holds a Server instance). */
const MAX_SESSIONS = parseInt(process.env.GATEWAY_MAX_SESSIONS || '', 10) || 64;

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

/** Extract license key from Authorization header (Bearer token) */
function extractLicenseKey(req: IncomingMessage): string | undefined {
  const auth = req.headers.authorization;
  if (!auth) return undefined;
  if (auth.startsWith('Bearer ')) return auth.slice(7).trim();
  return auth.trim();
}

// ---------------------------------------------------------------------------
// Access control
//
// Two very different deployments share this code:
//
//   Local (127.0.0.1)  — scans the developer's own project and returns their
//     source, including secret findings that embed the matched credential. The
//     risk is a web page reading it cross-origin, so CORS is allowlisted and
//     the Host header is checked against DNS rebinding.
//   Hosted (api.safeweave.dev) — a public multi-tenant API. Anonymous and
//     license-key callers are expected, so requests are NOT blanket-rejected;
//     instead the operations that read the server's own disk are gated.
// ---------------------------------------------------------------------------

const LOOPBACK_HOSTNAMES = new Set(['127.0.0.1', '::1', 'localhost']);

/**
 * Origins permitted to make browser (CORS) requests. Empty by default, which
 * means no browser origin can read a response. Never '*' — a wildcard here
 * defeats the loopback bind entirely, because any site the developer opens
 * could then read their local files cross-origin.
 */
const ALLOWED_ORIGINS = new Set(
  (process.env.GATEWAY_ALLOWED_ORIGINS || '')
    .split(',')
    .map((o) => o.trim())
    .filter(Boolean),
);

/**
 * Shared token identifying a trusted caller (e.g. our own dashboard). It is
 * NOT a blanket requirement: api.safeweave.dev is a deliberately public,
 * multi-tenant API, and CLI/MCP clients authenticate with a license key, not
 * this token. It only unlocks the operations that make the server read its
 * OWN filesystem — see canReadServerFiles().
 */
const AUTH_TOKEN = process.env.GATEWAY_AUTH_TOKEN || '';

function isLoopbackHost(host: string): boolean {
  return LOOPBACK_HOSTNAMES.has(host.replace(/^\[|\]$/g, ''));
}

/** Constant-time token comparison; digests so length never leaks. */
function hasValidToken(req: IncomingMessage): boolean {
  // No token configured means no caller can prove it is trusted. Returning
  // true here would have inverted the whole policy: a hosted instance with no
  // token would grant everyone server-side file access instead of nobody.
  if (!AUTH_TOKEN) return false;
  const provided = (req.headers['x-gateway-token'] as string | undefined) || '';
  if (!provided) return false;
  const a = createHash('sha256').update(provided).digest();
  const b = createHash('sha256').update(AUTH_TOKEN).digest();
  return timingSafeEqual(a, b);
}

export function startHttpBridge(projectDir: string): void {
  const config = loadConfig(projectDir);
  const router = new Router(config);
  const profileManager = new ProfileManager();
  const licenseClient = new LicenseClient(LICENSE_SERVER_URL);
  const licenseKey = config.licenseKey;

  const host = config.gateway.host;
  const port = config.gateway.port;

  // A hosted (non-loopback) instance serves anonymous callers by design, so it
  // must not be refused a start. Without a token it simply cannot be asked to
  // read its own filesystem — a safe default rather than a fatal one.
  if (!isLoopbackHost(host) && !AUTH_TOKEN) {
    console.warn(
      `[gateway] Bound ${host}:${port} without GATEWAY_AUTH_TOKEN — server-side path scanning ` +
      `(the "directory" parameter) is disabled. Content-based scans are unaffected.`,
    );
  }

  // --- SSE transport session store ---
  const sseSessions = new Map<string, SSEServerTransport>();

  // --- Streamable HTTP transport session store ---
  const streamableSessions = new Map<string, StreamableHTTPServerTransport>();

  // Each session holds an MCP Server instance, so an unbounded map is a memory
  // exhaustion vector. Cap the total and reject once full.
  const sessionCount = () => sseSessions.size + streamableSessions.size;

  const server = createHttpServer(async (req, res) => {
    // A browser only sends Origin on cross-origin requests. Answer CORS for
    // explicitly allowlisted origins and refuse every other one outright —
    // no wildcard, so an arbitrary page cannot read local scan results.
    const origin = req.headers.origin;
    if (origin) {
      if (!ALLOWED_ORIGINS.has(origin)) {
        sendJson(res, 403, { error: 'Origin not allowed' });
        return;
      }
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Vary', 'Origin');
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, Mcp-Session-Id, X-Gateway-Token');
      res.setHeader('Access-Control-Expose-Headers', 'Mcp-Session-Id');
    }

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    // DNS-rebinding defense. On a loopback bind, only accept requests whose
    // Host header is itself loopback: otherwise a hostile page can point its
    // own domain at 127.0.0.1, become same-origin, and skip CORS entirely.
    if (isLoopbackHost(host)) {
      const hostHeader = (req.headers.host || '').replace(/:\d+$/, '');
      if (!isLoopbackHost(hostHeader)) {
        sendJson(res, 403, { error: 'Invalid Host header' });
        return;
      }
    }

    const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
    const pathname = url.pathname;

    // May this caller make the server read its own filesystem? On a loopback
    // bind that filesystem is the developer's own project, which is the whole
    // point of running locally. On a hosted bind it is our container, so only
    // a caller holding the shared token may do it. Scanning caller-supplied
    // file CONTENT is unrestricted either way — that is the public API.
    const canReadServerFiles = isLoopbackHost(host) || hasValidToken(req);

    try {
      // ============================================================
      // Existing REST endpoints
      // ============================================================

      if (req.method === 'GET' && pathname === '/api/health') {
        const health = await router.healthCheck();
        sendJson(res, 200, { status: 'ok', scanners: health });
        return;
      }

      if (req.method === 'POST' && pathname === '/api/scan') {
        const rawBody = await readBody(req);
        const body = JSON.parse(rawBody) as {
          directory?: string;
          staged?: boolean;
          files?: Array<string | { path: string; content: string }>;
          scanners?: string[];
          target_url?: string;
          repo?: string;
        };

        // Attribution comes from the CALLER. This process's own projectDir is
        // our container on a hosted deploy, so deriving a slug from it would
        // file every tenant's every repo under one name. Explicit `repo` wins;
        // otherwise fall back to the basename of the directory the caller
        // named. Unattributed scans all share one bucket and overwrite each
        // other in the per-repo view, which is why this matters.
        const reportedRepo =
          normalizeRepoSlug(body.repo) ?? normalizeRepoSlug(basename(body.directory || ''));

        // Normalize the three documented `files` shapes into one array of
        // {path, content}. The object map is what the public API docs show, and
        // it silently did the WRONG thing before: it has no `.length`, so it
        // fell through to scanning the server's own projectDir and returned
        // those findings as if they were the caller's.
        const clientFiles = normalizeClientFiles(body.files);

        // Caller-supplied CONTENT is the only mode that leaves the server's own
        // disk untouched. An explicit `directory`, bare path strings, AND a body
        // naming neither all end up reading local files — the last via the
        // projectDir fallback below. So gate on the resolution mode, not on the
        // presence of `directory`: keying off `directory` both missed the
        // fallback (a `{}` body scanned the server's filesystem) and rejected
        // clients that legitimately send `directory` alongside their content.
        const hasClientContent = clientFiles.length > 0;

        // A DAST run targets a URL over the network and reads no files at all,
        // so requiring content would refuse a legitimate scanners:["dast"] call.
        const isUrlOnlyScan =
          typeof body.target_url === 'string' &&
          body.target_url.length > 0 &&
          Array.isArray(body.scanners) &&
          body.scanners.length > 0 &&
          body.scanners.every((s) => URL_ONLY_SCANNERS.has(s));

        if (!hasClientContent && !isUrlOnlyScan && !canReadServerFiles) {
          sendJson(res, 403, {
            error: 'Scanning server-side paths is not permitted on this instance. ' +
                   'Send file contents instead: { "files": [{ "path": "...", "content": "..." }] }',
          });
          return;
        }

        const dir = body.directory || projectDir;
        const profile = profileManager.getActive();

        // Use client's license key from Authorization header, fall back to config
        const clientKey = extractLicenseKey(req) || licenseKey;

        // Determine blocked scanners based on license.
        //
        // The cloud runner is an internal caller that scans on a customer's
        // behalf but cannot present their license key — the license-server only
        // stores its hash. It therefore asserts the entitlement directly. This
        // is honoured ONLY for a caller holding GATEWAY_AUTH_TOKEN, i.e. the
        // same trust level already required to read server-side paths; an
        // anonymous caller sending this header is ignored entirely.
        // Honour the entitlement assertion ONLY for a caller proving the shared
        // token — not for any loopback caller, which on a 127.0.0.1-bound
        // gateway would let any local process bypass license feature-gating.
        const assertedScanners = hasValidToken(req)
          ? (req.headers['x-entitled-scanners'] as string | undefined)
          : undefined;
        const entitled = assertedScanners
          ? new Set(assertedScanners.split(',').map((s) => s.trim()).filter(Boolean))
          : null;

        const blocked: string[] = [];
        for (const s of GATED_SCANNERS) {
          const allowed = entitled
            ? entitled.has(s)
            : await licenseClient.isFeatureAllowed(clientKey, s);
          if (!allowed) blocked.push(s);
        }

        const blockedSet = new Set(blocked);
        let requestedScanners: Set<string> | undefined;
        if (body.scanners && body.scanners.length > 0) {
          requestedScanners = new Set(body.scanners);
        }

        // Resolve files: collect locally, use provided content, or use paths
        let scanFiles: Array<{ path: string; content?: string }>;
        let rootDir = dir;
        let cleanup = () => {};

        if (hasClientContent) {
          // Files with content provided (remote mode)
          const materialized = materializeFiles(clientFiles);
          rootDir = materialized.rootDir;
          scanFiles = clientFiles;
          cleanup = materialized.cleanup;
        } else if (isUrlOnlyScan) {
          // Nothing on disk to scan — the target is a URL.
          scanFiles = [];
        } else if (existsSync(dir)) {
          // Local mode — collect files from disk
          scanFiles = collectLocalFiles(dir);
        } else if (Array.isArray(body.files) && body.files.length > 0) {
          // Legacy: array of file paths (strings)
          scanFiles = (body.files as string[]).map((f) => ({ path: f }));
        } else {
          scanFiles = [{ path: dir }];
        }

        try {
          const result = await router.scanAll(
            {
              files: scanFiles,
              profile: { name: profile.name, rules: profile.rules as Record<string, unknown> },
              context: { rootDir, target_url: body.target_url },
            },
            blockedSet,
            requestedScanners,
          );

          if (blocked.length > 0) {
            result.findings.push(...upgradeFindings(blocked));
          }

          const scannerLabel = body.scanners?.join(',') || 'all';
          const durationMs = typeof result.metadata.duration_ms === 'number' ? result.metadata.duration_ms : 0;
          licenseClient.reportUsage(clientKey, scannerLabel, result.findings, durationMs, reportedRepo);

          sendJson(res, 200, result);
        } finally {
          cleanup();
        }
        return;
      }

      // ============================================================
      // SSE MCP transport (legacy — for Warp, Cursor, etc.)
      // GET /sse  — establish SSE stream
      // POST /messages?sessionId=<id>  — send messages to session
      // ============================================================

      if (req.method === 'GET' && pathname === '/sse') {
        if (sessionCount() >= MAX_SESSIONS) {
          sendJson(res, 503, { error: 'Too many active sessions' });
          return;
        }
        const clientKey = extractLicenseKey(req);
        const mcpServer = createMcpServer(projectDir, clientKey, canReadServerFiles, true);

        const transport = new SSEServerTransport('/messages', res);
        sseSessions.set(transport.sessionId, transport);

        transport.onclose = () => {
          sseSessions.delete(transport.sessionId);
        };

        await mcpServer.connect(transport);
        console.log(`SSE session established: ${transport.sessionId}`);
        return;
      }

      if (req.method === 'POST' && pathname === '/messages') {
        const sessionId = url.searchParams.get('sessionId');
        if (!sessionId) {
          sendJson(res, 400, { error: 'Missing sessionId query parameter' });
          return;
        }

        const transport = sseSessions.get(sessionId);
        if (!transport) {
          sendJson(res, 404, { error: 'Session not found. It may have expired.' });
          return;
        }

        await transport.handlePostMessage(req, res);
        return;
      }

      // ============================================================
      // Streamable HTTP MCP transport (modern)
      // POST /mcp  — send JSON-RPC messages (initialize or ongoing)
      // GET  /mcp  — establish SSE stream for server-initiated messages
      // DELETE /mcp — terminate session
      // ============================================================

      if (pathname === '/mcp') {
        const sessionId = req.headers['mcp-session-id'] as string | undefined;

        if (req.method === 'POST') {
          // Check for existing session
          let transport = sessionId ? streamableSessions.get(sessionId) : undefined;

          // A POST carrying an unknown session id is not an initialize; building
          // a fresh transport + MCP Server for it would leak one of each per
          // request, since only initialize triggers onsessioninitialized.
          if (!transport && sessionId) {
            sendJson(res, 404, { error: 'Session not found' });
            return;
          }

          if (!transport && sessionCount() >= MAX_SESSIONS) {
            sendJson(res, 503, { error: 'Too many active sessions' });
            return;
          }

          if (!transport) {
            // New session — create transport and MCP server
            const clientKey = extractLicenseKey(req);
            transport = new StreamableHTTPServerTransport({
              sessionIdGenerator: () => crypto.randomUUID(),
              onsessioninitialized: (sid) => {
                streamableSessions.set(sid, transport!);
                console.log(`Streamable HTTP session established: ${sid}`);
              },
            });

            transport.onclose = () => {
              if (transport!.sessionId) {
                streamableSessions.delete(transport!.sessionId);
              }
            };

            const mcpServer = createMcpServer(projectDir, clientKey, canReadServerFiles, true);
            await mcpServer.connect(transport);
          }

          await transport.handleRequest(req, res);
          return;
        }

        if (req.method === 'GET') {
          // SSE stream for server-initiated messages
          if (!sessionId) {
            sendJson(res, 400, { error: 'Missing Mcp-Session-Id header' });
            return;
          }
          const transport = streamableSessions.get(sessionId);
          if (!transport) {
            sendJson(res, 404, { error: 'Session not found' });
            return;
          }
          await transport.handleRequest(req, res);
          return;
        }

        if (req.method === 'DELETE') {
          if (!sessionId) {
            sendJson(res, 400, { error: 'Missing Mcp-Session-Id header' });
            return;
          }
          const transport = streamableSessions.get(sessionId);
          if (!transport) {
            sendJson(res, 404, { error: 'Session not found' });
            return;
          }
          await transport.handleRequest(req, res);
          streamableSessions.delete(sessionId);
          return;
        }
      }

      sendJson(res, 404, { error: 'Not found' });
    } catch (err) {
      if ((err as { statusCode?: number })?.statusCode === 413) {
        sendJson(res, 413, { error: 'Request body too large' });
        return;
      }
      console.error('HTTP bridge error:', err);
      sendJson(res, 500, { error: 'Internal server error' });
    }
  });

  server.listen(port, host, () => {
    console.log(`SafeWeave HTTP bridge listening on http://${host}:${port}`);
    console.log(`  REST API: /api/health, /api/scan`);
    console.log(`  MCP SSE:  GET /sse, POST /messages`);
    console.log(`  MCP HTTP: POST|GET|DELETE /mcp`);
  });
}
