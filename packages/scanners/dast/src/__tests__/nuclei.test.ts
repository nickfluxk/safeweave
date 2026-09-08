import { describe, it, expect, vi, beforeEach } from 'vitest';
import { runNuclei, isUnsafeTarget } from '../nuclei.js';
import type { ScanRequest } from '@safeweave/common';

vi.mock('node:child_process', () => ({
  execFile: vi.fn(),
}));

import { execFile } from 'node:child_process';

const mockExecFile = vi.mocked(execFile);

function makeScanRequest(overrides?: Partial<ScanRequest>): ScanRequest {
  return {
    files: [],
    profile: { name: 'standard', rules: {} },
    context: { target_url: 'https://example.com' },
    ...overrides,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe('runNuclei', () => {
  it('parses Nuclei JSONL output into findings', async () => {
    const nucleiLines = [
      JSON.stringify({
        'template-id': 'cve-2021-44228',
        'matched-at': 'https://example.com/api',
        info: {
          name: 'Log4j RCE',
          severity: 'critical',
          description: 'Remote code execution via Log4j',
          remediation: 'Upgrade Log4j to 2.17.0+',
          classification: { cwe: ['CWE-502'] },
        },
      }),
      JSON.stringify({
        'template-id': 'xss-reflected',
        'matched-at': 'https://example.com/search?q=test',
        info: {
          name: 'Reflected XSS',
          severity: 'medium',
          description: 'Reflected cross-site scripting',
        },
      }),
    ].join('\n');

    mockExecFile.mockImplementation((_cmd, _args, _opts, callback) => {
      (callback as Function)(null, nucleiLines, '');
      return {} as ReturnType<typeof execFile>;
    });

    const { findings } = await runNuclei(makeScanRequest());

    expect(findings).toHaveLength(2);
    expect(findings[0].id).toBe('DAST-cve-2021-44228');
    expect(findings[0].severity).toBe('critical');
    expect(findings[0].title).toBe('Log4j RCE');
    expect(findings[0].remediation).toBe('Upgrade Log4j to 2.17.0+');
    expect(findings[0].cwe).toBe('CWE-502');

    expect(findings[1].id).toBe('DAST-xss-reflected');
    expect(findings[1].severity).toBe('medium');
    expect(findings[1].title).toBe('Reflected XSS');
  });

  it('returns empty findings when no target_url provided', async () => {
    const { findings } = await runNuclei(makeScanRequest({
      context: {},
    }));
    expect(findings).toEqual([]);
    expect(mockExecFile).not.toHaveBeenCalled();
  });

  it('returns empty findings when nuclei is not installed', async () => {
    mockExecFile.mockImplementation((_cmd, _args, _opts, callback) => {
      (callback as Function)(new Error('ENOENT'), '', '');
      return {} as ReturnType<typeof execFile>;
    });

    const { findings } = await runNuclei(makeScanRequest());
    expect(findings).toEqual([]);
  });

  it('returns empty findings on invalid JSON lines', async () => {
    mockExecFile.mockImplementation((_cmd, _args, _opts, callback) => {
      (callback as Function)(null, 'not valid json\nalso not json\n', '');
      return {} as ReturnType<typeof execFile>;
    });

    const { findings } = await runNuclei(makeScanRequest());
    expect(findings).toEqual([]);
  });

  it('refuses to scan loopback/internal/private targets (SSRF guard)', async () => {
    for (const url of [
      'http://localhost:3000',
      'http://127.0.0.1/admin',
      'http://169.254.169.254/latest/meta-data/',
      'http://10.0.0.5',
      'http://192.168.1.1',
      'http://172.16.0.9',
      'http://db.internal/health',
    ]) {
      expect(isUnsafeTarget(url)).toBe(true);
      const { findings } = await runNuclei(makeScanRequest({ context: { target_url: url } }));
      expect(findings).toEqual([]);
    }
    expect(mockExecFile).not.toHaveBeenCalled();
  });

  it('allows public targets', () => {
    expect(isUnsafeTarget('https://example.com')).toBe(false);
    expect(isUnsafeTarget('https://api.safeweave.dev/health')).toBe(false);
  });

  it('passes target_url to nuclei command', async () => {
    mockExecFile.mockImplementation((_cmd, _args, _opts, callback) => {
      (callback as Function)(null, '', '');
      return {} as ReturnType<typeof execFile>;
    });

    await runNuclei(makeScanRequest());

    expect(mockExecFile).toHaveBeenCalledWith(
      'nuclei',
      ['-u', 'https://example.com', '-jsonl', '-silent'],
      expect.any(Object),
      expect.any(Function),
    );
  });
});

describe('isUnsafeTarget — SSRF guard', () => {
  // URL.hostname returns IPv6 literals wrapped in brackets ('[::1]'), so the
  // original bare-literal comparisons matched nothing and every IPv6 internal
  // target passed as safe — turning DAST into an SSRF probe against the
  // scanner host's own loopback and cloud metadata.
  it.each([
    'http://[::1]:9001/',
    'http://[::]:8080/',
    'http://[::ffff:127.0.0.1]/',   // normalizes to ::ffff:7f00:1
    'http://[::ffff:169.254.169.254]/', // cloud metadata via mapped v6
    'http://[fd00::1]/',
    'http://[fc00::1234]/',
    'http://[fe80::1]/',
  ])('refuses IPv6 internal target %s', (url) => {
    expect(isUnsafeTarget(url)).toBe(true);
  });

  it.each([
    'http://127.0.0.1/',
    'http://10.1.2.3/',
    'http://192.168.1.1/',
    'http://172.16.0.1/',
    'http://169.254.169.254/',
    'http://localhost/',
    'http://foo.internal/',
  ])('refuses IPv4/name internal target %s', (url) => {
    expect(isUnsafeTarget(url)).toBe(true);
  });

  it.each([
    'https://example.com/',
    'https://8.8.8.8/',
    'http://[2606:4700:4700::1111]/',
  ])('allows genuine public target %s', (url) => {
    expect(isUnsafeTarget(url)).toBe(false);
  });

  it('refuses a malformed URL rather than defaulting to allowed', () => {
    expect(isUnsafeTarget('not a url')).toBe(true);
  });
});
