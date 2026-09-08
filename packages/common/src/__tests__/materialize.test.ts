import { describe, it, expect, afterEach } from 'vitest';
import { readFileSync, existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { safeJoin, materializeFiles } from '../materialize.js';

describe('safeJoin', () => {
  const root = '/tmp/safeweave-root';

  it('joins a normal relative path under root', () => {
    expect(safeJoin(root, 'src/app.ts')).toBe(resolve(root, 'src/app.ts'));
  });

  it('allows the root itself', () => {
    expect(safeJoin(root, '.')).toBe(resolve(root));
  });

  it('rejects parent-directory traversal', () => {
    expect(() => safeJoin(root, '../../etc/passwd')).toThrow(/escapes root/);
  });

  it('rejects deep traversal that lands outside root', () => {
    expect(() => safeJoin(root, 'a/b/../../../../home/user/.bashrc')).toThrow(/escapes root/);
  });

  it('rejects absolute paths', () => {
    expect(() => safeJoin(root, '/etc/passwd')).toThrow(/escapes root/);
  });

  it('does not treat a sibling dir with the same prefix as inside root', () => {
    // /tmp/safeweave-root-evil must NOT be considered under /tmp/safeweave-root
    expect(() => safeJoin(root, '../safeweave-root-evil/x')).toThrow(/escapes root/);
  });
});

describe('materializeFiles', () => {
  const cleanups: Array<() => void> = [];
  afterEach(() => {
    cleanups.forEach((c) => c());
    cleanups.length = 0;
  });

  it('writes files with content into a temp dir', () => {
    const m = materializeFiles([
      { path: 'requirements.txt', content: 'flask==1.0\n' },
      { path: 'src/main.py', content: 'print(1)\n' },
    ]);
    cleanups.push(m.cleanup);
    expect(m.written).toBe(2);
    expect(readFileSync(join(m.dir, 'requirements.txt'), 'utf8')).toBe('flask==1.0\n');
    expect(readFileSync(join(m.dir, 'src/main.py'), 'utf8')).toBe('print(1)\n');
  });

  it('skips (does not write) traversal paths instead of escaping the temp dir', () => {
    const m = materializeFiles([
      { path: '../../evil.txt', content: 'pwned' },
      { path: 'ok.txt', content: 'fine' },
    ]);
    cleanups.push(m.cleanup);
    expect(m.written).toBe(1);
    expect(m.skipped).toContain('../../evil.txt');
    expect(existsSync(join(m.dir, 'ok.txt'))).toBe(true);
  });

  it('ignores files without content', () => {
    const m = materializeFiles([{ path: 'a.txt' }]);
    cleanups.push(m.cleanup);
    expect(m.written).toBe(0);
  });

  it('cleanup removes the temp dir', () => {
    const m = materializeFiles([{ path: 'a.txt', content: 'x' }]);
    const dir = m.dir;
    expect(existsSync(dir)).toBe(true);
    m.cleanup();
    expect(existsSync(dir)).toBe(false);
  });
});
