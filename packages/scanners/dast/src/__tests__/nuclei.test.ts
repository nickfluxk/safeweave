import { describe, it, expect, vi, beforeEach } from 'vitest';
import { runNuclei } from '../nuclei.js';
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

    const findings = await runNuclei(makeScanRequest());

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
    const findings = await runNuclei(makeScanRequest({
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

    const findings = await runNuclei(makeScanRequest());
    expect(findings).toEqual([]);
  });

  it('returns empty findings on invalid JSON lines', async () => {
    mockExecFile.mockImplementation((_cmd, _args, _opts, callback) => {
      (callback as Function)(null, 'not valid json\nalso not json\n', '');
      return {} as ReturnType<typeof execFile>;
    });

    const findings = await runNuclei(makeScanRequest());
    expect(findings).toEqual([]);
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
