import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createServer } from '../server.js';
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

describe('Secret Detector HTTP Server', () => {
  it('responds to health check', async () => {
    const res = await fetch(`${baseUrl}/health`);
    expect(res.ok).toBe(true);
    const body = await res.json();
    expect(body.scanner).toBe('secrets');
  });

  it('accepts scan request', async () => {
    const res = await fetch(`${baseUrl}/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        files: [{ path: 'config.js', content: 'const API_KEY = "AKIAIOSFODNN7EXAMPLE"' }],
        profile: { name: 'standard', rules: {} },
        context: {},
      }),
    });
    expect(res.ok).toBe(true);
    const body = await res.json();
    expect(Array.isArray(body.findings)).toBe(true);
    expect(body.metadata.scanner).toBe('secrets');
  });
});
