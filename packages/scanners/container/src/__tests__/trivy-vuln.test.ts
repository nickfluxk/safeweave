import { describe, it, expect, vi, beforeEach } from 'vitest';
import { runTrivyVuln } from '../trivy-vuln.js';
import type { ScanRequest } from '@safeweave/common';

vi.mock('node:child_process', () => ({
  execFile: vi.fn(),
}));

import { execFile } from 'node:child_process';

const mockExecFile = vi.mocked(execFile);

function makeScanRequest(overrides?: Partial<ScanRequest>): ScanRequest {
  return {
    files: [{ path: 'Dockerfile', content: 'FROM node:20' }],
    profile: { name: 'standard', rules: {} },
    context: { rootDir: '/tmp/test-project' },
    ...overrides,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe('runTrivyVuln', () => {
  it('parses Trivy vulnerability JSON output into findings', async () => {
    const trivyOutput = {
      Results: [
        {
          Target: 'package-lock.json',
          Vulnerabilities: [
            {
              VulnerabilityID: 'CVE-2023-1234',
              PkgName: 'lodash',
              InstalledVersion: '4.17.20',
              FixedVersion: '4.17.21',
              Title: 'Prototype Pollution in lodash',
              Severity: 'CRITICAL',
              CweIDs: ['CWE-1321'],
            },
            {
              VulnerabilityID: 'CVE-2023-5678',
              PkgName: 'express',
              InstalledVersion: '4.17.0',
              FixedVersion: '',
              Description: 'Open redirect vulnerability',
              Severity: 'MEDIUM',
            },
          ],
        },
      ],
    };

    mockExecFile.mockImplementation((_cmd, _args, _opts, callback) => {
      (callback as Function)(null, JSON.stringify(trivyOutput), '');
      return {} as ReturnType<typeof execFile>;
    });

    const findings = await runTrivyVuln(makeScanRequest());

    expect(findings).toHaveLength(2);
    expect(findings[0].id).toBe('CONTAINER-CVE-2023-1234');
    expect(findings[0].severity).toBe('critical');
    expect(findings[0].title).toBe('CVE-2023-1234: lodash@4.17.20');
    expect(findings[0].remediation).toBe('Upgrade lodash to 4.17.21');
    expect(findings[0].cwe).toBe('CWE-1321');

    expect(findings[1].id).toBe('CONTAINER-CVE-2023-5678');
    expect(findings[1].severity).toBe('medium');
    expect(findings[1].remediation).toBe('No fix available — consider alternative package');
    expect(findings[1].cwe).toBeUndefined();
  });

  it('returns empty findings when trivy is not installed', async () => {
    mockExecFile.mockImplementation((_cmd, _args, _opts, callback) => {
      (callback as Function)(new Error('ENOENT'), '', '');
      return {} as ReturnType<typeof execFile>;
    });

    const findings = await runTrivyVuln(makeScanRequest());
    expect(findings).toEqual([]);
  });

  it('returns empty findings on invalid JSON', async () => {
    mockExecFile.mockImplementation((_cmd, _args, _opts, callback) => {
      (callback as Function)(null, 'not json', '');
      return {} as ReturnType<typeof execFile>;
    });

    const findings = await runTrivyVuln(makeScanRequest());
    expect(findings).toEqual([]);
  });

  it('handles empty Results array', async () => {
    mockExecFile.mockImplementation((_cmd, _args, _opts, callback) => {
      (callback as Function)(null, JSON.stringify({ Results: [] }), '');
      return {} as ReturnType<typeof execFile>;
    });

    const findings = await runTrivyVuln(makeScanRequest());
    expect(findings).toEqual([]);
  });
});
