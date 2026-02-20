import { existsSync } from 'node:fs';
import { join } from 'node:path';
import type { EcosystemAuditor } from './types.js';

export function detectEcosystems(rootDir: string, auditors: EcosystemAuditor[]): EcosystemAuditor[] {
  return auditors.filter((auditor) =>
    auditor.indicators.some((indicator) => existsSync(join(rootDir, indicator)))
  );
}
