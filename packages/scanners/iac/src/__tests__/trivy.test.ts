import { describe, it, expect, vi, beforeEach } from 'vitest';
import { runTrivyMisconfig } from '../trivy.js';
import type { ScanRequest } from '@safeweave/common';

vi.mock('node:child_process', () => ({
  execFile: vi.fn(),
}));

import { execFile } from 'node:child_process';

const mockExecFile = vi.mocked(execFile);

function makeScanRequest(overrides?: Partial<ScanRequest>): ScanRequest {
  return {
    files: [{ path: 'main.tf', content: 'resource "aws_s3_bucket" {}' }],
    profile: { name: 'standard', rules: {} },
    context: { rootDir: '/tmp/test-project' },
    ...overrides,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe('runTrivyMisconfig', () => {
  it('parses Trivy misconfig JSON output into findings', async () => {
    const trivyOutput = {
      Results: [
        {
          Target: 'main.tf',
          Misconfigurations: [
            {
              ID: 'AVD-AWS-0086',
              AVDID: 'AVD-AWS-0086',
              Title: 'S3 bucket does not have encryption enabled',
              Description: 'Unencrypted S3 bucket',
              Severity: 'HIGH',
              Resolution: 'Enable encryption on the S3 bucket',
            },
            {
              ID: 'AVD-AWS-0087',
              Title: 'S3 bucket versioning disabled',
              Description: 'Versioning is not enabled',
              Severity: 'MEDIUM',
              Resolution: 'Enable versioning',
            },
          ],
        },
      ],
    };

    mockExecFile.mockImplementation((_cmd, _args, _opts, callback) => {
      (callback as Function)(null, JSON.stringify(trivyOutput), '');
      return {} as ReturnType<typeof execFile>;
    });

    const findings = await runTrivyMisconfig(makeScanRequest());

    expect(findings).toHaveLength(2);
    expect(findings[0].id).toBe('IAC-AVD-AWS-0086');
    expect(findings[0].severity).toBe('high');
    expect(findings[0].title).toBe('S3 bucket does not have encryption enabled');
    expect(findings[0].file).toBe('main.tf');
    expect(findings[0].remediation).toBe('Enable encryption on the S3 bucket');

    expect(findings[1].id).toBe('IAC-AVD-AWS-0087');
    expect(findings[1].severity).toBe('medium');
  });

  it('returns empty findings when trivy is not installed', async () => {
    mockExecFile.mockImplementation((_cmd, _args, _opts, callback) => {
      (callback as Function)(new Error('ENOENT'), '', '');
      return {} as ReturnType<typeof execFile>;
    });

    const findings = await runTrivyMisconfig(makeScanRequest());
    expect(findings).toEqual([]);
  });

  it('returns empty findings on invalid JSON', async () => {
    mockExecFile.mockImplementation((_cmd, _args, _opts, callback) => {
      (callback as Function)(null, 'not json', '');
      return {} as ReturnType<typeof execFile>;
    });

    const findings = await runTrivyMisconfig(makeScanRequest());
    expect(findings).toEqual([]);
  });

  it('maps all severity levels correctly', async () => {
    const trivyOutput = {
      Results: [
        {
          Target: 'config.yaml',
          Misconfigurations: [
            { ID: 'C1', Severity: 'CRITICAL', Title: 'Critical issue', Resolution: 'Fix' },
            { ID: 'L1', Severity: 'LOW', Title: 'Low issue', Resolution: 'Fix' },
            { ID: 'U1', Severity: 'UNKNOWN', Title: 'Unknown', Resolution: 'Fix' },
          ],
        },
      ],
    };

    mockExecFile.mockImplementation((_cmd, _args, _opts, callback) => {
      (callback as Function)(null, JSON.stringify(trivyOutput), '');
      return {} as ReturnType<typeof execFile>;
    });

    const findings = await runTrivyMisconfig(makeScanRequest());
    expect(findings[0].severity).toBe('critical');
    expect(findings[1].severity).toBe('low');
    expect(findings[2].severity).toBe('info');
  });

  it('uses process.cwd() when rootDir not specified', async () => {
    mockExecFile.mockImplementation((_cmd, _args, _opts, callback) => {
      (callback as Function)(null, '', '');
      return {} as ReturnType<typeof execFile>;
    });

    await runTrivyMisconfig({
      files: [],
      profile: { name: 'standard', rules: {} },
      context: {},
    });

    expect(mockExecFile).toHaveBeenCalledWith(
      'trivy',
      ['fs', '--scanners', 'misconfig', '--format', 'json', process.cwd()],
      expect.any(Object),
      expect.any(Function),
    );
  });
});
