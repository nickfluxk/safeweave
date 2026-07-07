import { describe, it, expect, vi, beforeEach } from 'vitest';
import { runLicenseCheck } from '../license-check.js';
import type { ScanRequest } from '@safeweave/common';

vi.mock('node:child_process', () => ({
  execFile: vi.fn(),
}));

vi.mock('node:fs', () => ({
  existsSync: vi.fn(),
}));

import { execFile } from 'node:child_process';
import { existsSync } from 'node:fs';

const mockExecFile = vi.mocked(execFile);
const mockExistsSync = vi.mocked(existsSync);

function makeScanRequest(overrides?: Partial<ScanRequest>): ScanRequest {
  return {
    files: [{ path: 'package.json', content: '{}' }],
    profile: { name: 'standard', rules: {} },
    context: { rootDir: '/tmp/test-project' },
    ...overrides,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe('runLicenseCheck', () => {
  it('detects blocked npm licenses', async () => {
    mockExistsSync.mockImplementation((p) => {
      const path = String(p);
      return path.endsWith('package.json');
    });

    const npmOutput = {
      'lodash@4.17.21': { licenses: 'MIT' },
      'gpl-package@1.0.0': { licenses: 'GPL-3.0' },
      'another-gpl@2.0.0': { licenses: 'AGPL-3.0-only' },
    };

    mockExecFile.mockImplementation((_cmd, _args, _opts, callback) => {
      (callback as Function)(null, JSON.stringify(npmOutput), '');
      return {} as ReturnType<typeof execFile>;
    });

    const findings = await runLicenseCheck(makeScanRequest());

    expect(findings).toHaveLength(2);
    expect(findings[0].id).toBe('LICENSE-npm-gpl-package');
    expect(findings[0].severity).toBe('high');
    expect(findings[0].title).toContain('GPL-3.0');
    expect(findings[0].file).toBe('package.json');

    expect(findings[1].id).toBe('LICENSE-npm-another-gpl');
    expect(findings[1].title).toContain('AGPL-3.0');
  });

  it('returns empty findings when no ecosystems detected', async () => {
    mockExistsSync.mockReturnValue(false);

    const findings = await runLicenseCheck(makeScanRequest());
    expect(findings).toEqual([]);
    expect(mockExecFile).not.toHaveBeenCalled();
  });

  it('returns empty findings when license-checker is not installed', async () => {
    mockExistsSync.mockImplementation((p) => {
      return String(p).endsWith('package.json');
    });

    mockExecFile.mockImplementation((_cmd, _args, _opts, callback) => {
      (callback as Function)(new Error('ENOENT'), '', '');
      return {} as ReturnType<typeof execFile>;
    });

    const findings = await runLicenseCheck(makeScanRequest());
    expect(findings).toEqual([]);
  });

  it('uses custom blocked_licenses from profile rules', async () => {
    mockExistsSync.mockImplementation((p) => {
      return String(p).endsWith('package.json');
    });

    const npmOutput = {
      'mit-pkg@1.0.0': { licenses: 'MIT' },
      'apache-pkg@1.0.0': { licenses: 'Apache-2.0' },
    };

    mockExecFile.mockImplementation((_cmd, _args, _opts, callback) => {
      (callback as Function)(null, JSON.stringify(npmOutput), '');
      return {} as ReturnType<typeof execFile>;
    });

    const findings = await runLicenseCheck(makeScanRequest({
      profile: {
        name: 'custom',
        rules: { blocked_licenses: ['MIT'] },
      },
    }));

    expect(findings).toHaveLength(1);
    expect(findings[0].title).toContain('MIT');
    expect(findings[0].title).toContain('mit-pkg');
  });

  it('handles both npm and python ecosystems', async () => {
    mockExistsSync.mockImplementation((p) => {
      const path = String(p);
      return path.endsWith('package.json') || path.endsWith('requirements.txt');
    });

    const npmOutput = {
      'clean-pkg@1.0.0': { licenses: 'MIT' },
    };

    const pipOutput = [
      { Name: 'gpl-py-pkg', Version: '1.0.0', License: 'GPL-3.0' },
    ];

    let callCount = 0;
    mockExecFile.mockImplementation((_cmd, _args, _opts, callback) => {
      callCount++;
      const output = callCount === 1 ? JSON.stringify(npmOutput) : JSON.stringify(pipOutput);
      (callback as Function)(null, output, '');
      return {} as ReturnType<typeof execFile>;
    });

    const findings = await runLicenseCheck(makeScanRequest());

    expect(findings).toHaveLength(1);
    expect(findings[0].id).toContain('gpl-py-pkg');
  });
});
