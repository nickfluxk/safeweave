import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { safeJoin } from '@safeweave/common';

// collectLocalFiles moved to @safeweave/common so the CLI can reuse it; it is
// re-exported here to keep this module's existing importers unchanged.
export { collectLocalFiles } from '@safeweave/common';

export interface FileTarget {
  path: string;
  content: string;
}

export interface MaterializedDir {
  rootDir: string;
  cleanup: () => void;
}

/**
 * Write client-provided files into a temporary directory.
 * Returns the temp rootDir and a cleanup function.
 */
export function materializeFiles(files: FileTarget[]): MaterializedDir {
  const rootDir = mkdtempSync(join(tmpdir(), 'safeweave-'));

  for (const file of files) {
    let fullPath: string;
    try {
      // Contain the client-supplied path within rootDir (blocks ../ traversal).
      fullPath = safeJoin(rootDir, file.path);
    } catch {
      // Skip paths that try to escape the temp dir.
      continue;
    }
    mkdirSync(dirname(fullPath), { recursive: true });
    writeFileSync(fullPath, file.content);
  }

  return {
    rootDir,
    cleanup: () => {
      try {
        rmSync(rootDir, { recursive: true, force: true });
      } catch {
        // Best-effort cleanup
      }
    },
  };
}
