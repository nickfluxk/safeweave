import type { Finding } from '@safeweave/common';

export type Ecosystem = 'npm' | 'python' | 'go' | 'rust' | 'ruby';

export interface EcosystemAuditor {
  prefix: string;
  ecosystem: Ecosystem;
  indicators: string[];
  manifestFile: string;
  audit(rootDir: string): Promise<Finding[]>;
}
