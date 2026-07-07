import { describe, it, expect, vi, beforeEach } from 'vitest';
import { detectEcosystems } from '../detect.js';
import type { EcosystemAuditor } from '../types.js';

vi.mock('node:fs', () => ({
  existsSync: vi.fn(),
}));

import { existsSync } from 'node:fs';
const mockExistsSync = vi.mocked(existsSync);

function makeAuditor(overrides: Partial<EcosystemAuditor>): EcosystemAuditor {
  return {
    prefix: 'TEST',
    ecosystem: 'npm',
    indicators: ['package-lock.json'],
    manifestFile: 'package.json',
    audit: vi.fn().mockResolvedValue([]),
    ...overrides,
  };
}

beforeEach(() => {
  mockExistsSync.mockReset();
});

describe('detectEcosystems', () => {
  it('returns auditors whose indicator files exist', () => {
    const npm = makeAuditor({ prefix: 'NPM', indicators: ['package-lock.json', 'package.json'] });
    const pip = makeAuditor({ prefix: 'PIP', ecosystem: 'python', indicators: ['requirements.txt'] });

    mockExistsSync.mockImplementation((p) => {
      const path = String(p);
      return path.includes('package-lock.json') || path.includes('requirements.txt');
    });

    const detected = detectEcosystems('/project', [npm, pip]);
    expect(detected).toEqual([npm, pip]);
  });

  it('excludes auditors with no matching indicators', () => {
    const npm = makeAuditor({ prefix: 'NPM', indicators: ['package-lock.json'] });
    const pip = makeAuditor({ prefix: 'PIP', ecosystem: 'python', indicators: ['requirements.txt'] });

    mockExistsSync.mockReturnValue(false);

    const detected = detectEcosystems('/project', [npm, pip]);
    expect(detected).toEqual([]);
  });

  it('detects auditor when any indicator matches', () => {
    const go = makeAuditor({ prefix: 'GO', ecosystem: 'go', indicators: ['go.sum', 'go.mod'] });

    mockExistsSync.mockImplementation((p) => String(p).includes('go.mod'));

    const detected = detectEcosystems('/project', [go]);
    expect(detected).toEqual([go]);
  });

  it('returns empty array for empty auditor list', () => {
    const detected = detectEcosystems('/project', []);
    expect(detected).toEqual([]);
  });
});
