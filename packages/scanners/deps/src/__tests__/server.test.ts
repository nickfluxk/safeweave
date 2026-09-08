import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createServer, ALL_AUDITORS } from '../server.js';
import type { AddressInfo } from 'node:net';

let server: ReturnType<typeof createServer>;
let baseUrl: string;

beforeAll(async () => {
  server = createServer();
  await new Promise<void>((resolve) => {
    server.listen(0, () => {
      const addr = server.address() as AddressInfo;
      baseUrl = `http://127.0.0.1:${addr.port}`;
      resolve();
    });
  });
});

afterAll(() => { server.close(); });

// These two exercise the real `npm audit`, which reaches the network. Under a
// loaded parallel test run that comfortably exceeds vitest's 5s default, which
// made the suite intermittently red — the same failure shape as the SAST test.
const AUDIT_TIMEOUT_MS = 120_000;

describe('Dependency Auditor HTTP Server', () => {
  it('responds to health check', async () => {
    const res = await fetch(`${baseUrl}/health`);
    expect(res.ok).toBe(true);
    const body = await res.json();
    expect(body.scanner).toBe('deps');
  });

  it('accepts scan request', async () => {
    const res = await fetch(`${baseUrl}/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        files: [{ path: 'package.json' }],
        profile: { name: 'standard', rules: {} },
        context: { language: 'javascript' },
      }),
    });
    expect(res.ok).toBe(true);
    const body = await res.json();
    expect(Array.isArray(body.findings)).toBe(true);
    expect(body.metadata.scanner).toBe('deps');
  }, AUDIT_TIMEOUT_MS);

  it('returns findings with ecosystem-prefixed IDs', async () => {
    // Scan the monorepo root which has package.json
    const res = await fetch(`${baseUrl}/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        files: [{ path: 'package.json' }],
        profile: { name: 'standard', rules: {} },
        context: { language: 'javascript', rootDir: process.cwd() },
      }),
    });
    expect(res.ok).toBe(true);
    const body = await res.json();
    expect(Array.isArray(body.findings)).toBe(true);
    // If any findings exist, they should have the DEP-<ECOSYSTEM>- prefix
    for (const finding of body.findings) {
      expect(finding.id).toMatch(/^DEP-(NPM|PIP|GO|CARGO|GEM)-/);
    }
  }, AUDIT_TIMEOUT_MS);
});

describe('ALL_AUDITORS registry', () => {
  it('contains all five ecosystem auditors', () => {
    const prefixes = ALL_AUDITORS.map((a) => a.prefix);
    expect(prefixes).toEqual(['NPM', 'PIP', 'GO', 'CARGO', 'GEM']);
  });

  it('each auditor has required properties', () => {
    for (const auditor of ALL_AUDITORS) {
      expect(auditor.prefix).toBeTruthy();
      expect(auditor.ecosystem).toBeTruthy();
      expect(auditor.indicators.length).toBeGreaterThan(0);
      expect(auditor.manifestFile).toBeTruthy();
      expect(typeof auditor.audit).toBe('function');
    }
  });
});
