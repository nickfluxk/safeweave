import { describe, it, expect } from 'vitest';
import { runPostureChecks } from '../checks.js';
import type { ScanRequest } from '@safeweave/common';

const req = (files: ScanRequest['files'], rootDir?: string): ScanRequest => ({
  files,
  profile: { name: 'default', rules: {} },
  context: { rootDir },
} as ScanRequest);

describe('runPostureChecks path traversal guard', () => {
  // The scanner has no auth and sits on the internal network, so a direct
  // caller must never be able to steer the disk walk with context.rootDir.
  it('refuses a bare path escaping the service working directory', async () => {
    const out = await runPostureChecks(req([{ path: '/etc' }]));
    expect(out.findings).toEqual([]);
    expect(out.warnings.join(' ')).toMatch(/outside the scan root/);
  });

  it('ignores a client rootDir pointing at the filesystem root', async () => {
    // The old bug: rootDir:"/" + path:"." made requested===root and walked "/".
    const out = await runPostureChecks(req([{ path: '.' }], '/'));
    // Confined to cwd now, so it never returns host paths like /etc/passwd.
    expect(out.findings.every((f) => !f.file.startsWith('/etc'))).toBe(true);
  });

  it('still scans provided file content', async () => {
    const out = await runPostureChecks(
      req([{ path: 'a.js', content: 'x' }, { path: 'b.js', content: 'y' }]),
    );
    expect(Array.isArray(out.findings)).toBe(true);
  });
});
