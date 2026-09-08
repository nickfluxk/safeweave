import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execFileSync } from 'node:child_process';
import { createServer } from '../server.js';
import type { AddressInfo } from 'node:net';

// runSemgrep shells out to the real binary with `--config auto`, which pulls
// the rule registry over the network — several seconds, well past vitest's 5s
// default. And when semgrep is absent the scanner swallows the failure and
// returns [], so a bare `Array.isArray` assertion passes without exercising
// anything. Split the two: the contract test always runs with a timeout that
// fits a real semgrep invocation, and the detection test only runs where
// semgrep exists rather than silently asserting nothing.
const SEMGREP_TIMEOUT_MS = 120_000;

const hasSemgrep = (() => {
  try {
    execFileSync('semgrep', ['--version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
})();

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

afterAll(() => {
  server.close();
});

describe('SAST Scanner HTTP Server', () => {
  it('responds to health check', async () => {
    const res = await fetch(`${baseUrl}/health`);
    expect(res.ok).toBe(true);
    const body = await res.json();
    expect(body.status).toBe('healthy');
    expect(body.scanner).toBe('sast');
  });

  async function scanEval() {
    const res = await fetch(`${baseUrl}/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        files: [{ path: 'test.js', content: 'eval(userInput)' }],
        profile: { name: 'standard', rules: {} },
        context: { language: 'javascript' },
      }),
    });
    expect(res.ok).toBe(true);
    return res.json();
  }

  it('accepts scan request and returns findings array', async () => {
    const body = await scanEval();
    expect(Array.isArray(body.findings)).toBe(true);
    expect(body.metadata.scanner).toBe('sast');
    expect(body.metadata.files_scanned).toBe(1);
  }, SEMGREP_TIMEOUT_MS);

  it.skipIf(!hasSemgrep)('detects eval() in a scanned file', async () => {
    const body = await scanEval();
    expect(body.findings.length).toBeGreaterThan(0);
    const evalFinding = body.findings.find((f: { id: string }) => /eval/i.test(f.id));
    expect(evalFinding).toBeDefined();
    expect(evalFinding.file).toBe('test.js');
  }, SEMGREP_TIMEOUT_MS);
});
