import { writeFileSync, mkdtempSync, mkdirSync, rmSync } from 'node:fs';
import { join, dirname, resolve, sep } from 'node:path';
import { tmpdir } from 'node:os';
import type { FileTarget } from './types.js';

/**
 * Safely resolve a user-supplied (relative) path under a root directory.
 *
 * Throws if the resulting path would escape `rootDir` — this blocks path
 * traversal / zip-slip via crafted `file.path` values like `../../etc/passwd`
 * or absolute paths. Always use this before writing attacker-controlled paths.
 */
export function safeJoin(rootDir: string, userPath: string): string {
  const resolvedRoot = resolve(rootDir);
  const target = resolve(resolvedRoot, userPath);
  // Must be the root itself, or strictly under it (root + path separator).
  if (target !== resolvedRoot && !target.startsWith(resolvedRoot + sep)) {
    throw new Error(`Unsafe path rejected (escapes root): ${userPath}`);
  }
  return target;
}

export interface Materialized {
  /** Absolute path to the temp directory holding the written files. */
  dir: string;
  /** Number of files actually written. */
  written: number;
  /** Paths that were rejected because they escaped the root (traversal). */
  skipped: string[];
  /** Remove the temp directory. Call in a `finally`. */
  cleanup: () => void;
}

/**
 * Write a scan request's `files[]` (those with content) into a fresh, isolated
 * temp directory, containing every path within that directory. Paths that try
 * to escape the temp dir are skipped (and reported in `skipped`) rather than
 * written, so a malicious `file.path` can never overwrite host files.
 *
 * Scanners should materialize the request files and run their tool against the
 * returned `dir` — this is what makes file-based scanning work in distributed
 * deployments where the request's `context.rootDir` lives on a different host.
 */
export function materializeFiles(files: FileTarget[], prefix = 'safeweave-'): Materialized {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  let written = 0;
  const skipped: string[] = [];

  for (const file of files || []) {
    if (file.content == null) continue;
    let filePath: string;
    try {
      filePath = safeJoin(dir, file.path);
    } catch {
      skipped.push(file.path);
      continue;
    }
    mkdirSync(dirname(filePath), { recursive: true });
    writeFileSync(filePath, file.content);
    written++;
  }

  return {
    dir,
    written,
    skipped,
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}
