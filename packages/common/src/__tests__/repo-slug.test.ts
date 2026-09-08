import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { deriveRepoSlug, normalizeRepoSlug } from '../collect.js';

// Scans are grouped per repo and read back with DISTINCT ON (repo). Two repos
// that resolve to the same slug — or to no slug — share one bucket, where each
// scan overwrites the previous one and the two projects' scores get mixed up.
// These tests pin the "different project => different slug" property.

let root: string;

beforeAll(() => {
  root = mkdtempSync(join(tmpdir(), 'safeweave-slug-'));
});

afterAll(() => {
  rmSync(root, { recursive: true, force: true });
});

function repoWithRemote(name: string, url: string): string {
  const dir = join(root, name);
  mkdirSync(join(dir, '.git'), { recursive: true });
  writeFileSync(join(dir, '.git', 'config'), `[remote "origin"]\n\turl = ${url}\n`);
  return dir;
}

describe('normalizeRepoSlug', () => {
  it('lowercases and strips characters outside the slug charset', () => {
    expect(normalizeRepoSlug('  MyOrg/My Repo!  ')).toBe('myorg/myrepo');
  });

  it('returns undefined for empty or unusable input', () => {
    expect(normalizeRepoSlug('')).toBeUndefined();
    expect(normalizeRepoSlug(null)).toBeUndefined();
    expect(normalizeRepoSlug(undefined)).toBeUndefined();
    expect(normalizeRepoSlug('!!!')).toBeUndefined();
  });

  it('bounds the value to the repo column width', () => {
    expect(normalizeRepoSlug('a'.repeat(500))!.length).toBeLessThanOrEqual(200);
  });
});

describe('deriveRepoSlug', () => {
  it('reads an owner/repo slug from an SSH remote', () => {
    expect(deriveRepoSlug(repoWithRemote('ssh', 'git@github.com:SafeWeave/Gateway.git')))
      .toBe('safeweave/gateway');
  });

  it('reads an owner/repo slug from an HTTPS remote', () => {
    expect(deriveRepoSlug(repoWithRemote('https', 'https://github.com/safeweave/cli')))
      .toBe('safeweave/cli');
  });

  it('gives two different repos two different slugs', () => {
    const a = repoWithRemote('a', 'git@github.com:acme/api.git');
    const b = repoWithRemote('b', 'git@github.com:acme/web.git');
    expect(deriveRepoSlug(a)).not.toBe(deriveRepoSlug(b));
  });

  it('falls back to the directory name when there is no git remote', () => {
    const dir = join(root, 'NoGitHere');
    mkdirSync(dir, { recursive: true });
    expect(deriveRepoSlug(dir)).toBe('nogithere');
  });

  it('still separates two non-git projects by directory name', () => {
    const a = join(root, 'plain-one');
    const b = join(root, 'plain-two');
    mkdirSync(a, { recursive: true });
    mkdirSync(b, { recursive: true });
    expect(deriveRepoSlug(a)).not.toBe(deriveRepoSlug(b));
  });
});
