import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parse as parseYaml } from 'yaml';
import type { Profile } from '@safeweave/common';

const BUILT_IN_PROFILES: Record<string, Profile> = {
  standard: {
    name: 'standard',
    version: '1.0',
    description: 'Standard security profile — OWASP Top 10, common CVEs, secrets detection',
    severity_thresholds: { error: 'high', warn: 'medium' },
    rules: {
      sast: { enabled: true, rulesets: ['owasp-top-10'] },
      dependencies: { enabled: true, max_cvss_score: 7.0, require_lockfile: true },
      secrets: { enabled: true },
    },
  },
  hardened: {
    name: 'hardened',
    version: '1.0',
    description: 'Hardened security profile — strict thresholds, crypto requirements',
    severity_thresholds: { error: 'medium', warn: 'low' },
    rules: {
      sast: {
        enabled: true,
        rulesets: ['owasp-top-10', 'crypto-best-practices', 'auth-best-practices'],
        custom_rules: ['enforce-tls-1.2-minimum', 'no-eval', 'no-dynamic-require'],
      },
      dependencies: {
        enabled: true,
        max_cvss_score: 4.0,
        blocked_licenses: ['AGPL-3.0'],
        require_lockfile: true,
      },
      secrets: { enabled: true },
    },
  },
  owasp: {
    name: 'owasp',
    version: '1.0',
    description: 'OWASP Top 10 focused profile',
    severity_thresholds: { error: 'high', warn: 'medium' },
    rules: {
      sast: {
        enabled: true,
        rulesets: ['owasp-top-10', 'injection', 'xss', 'ssrf', 'broken-access-control'],
        custom_rules: ['no-eval', 'no-innerHTML', 'enforce-parameterized-queries'],
      },
      dependencies: { enabled: true, max_cvss_score: 7.0, require_lockfile: true },
      secrets: { enabled: true },
      iac: { enabled: true },
      dast: { enabled: true, checks: ['sql-injection', 'xss-reflected', 'xss-stored', 'ssrf', 'open-redirect'] },
    },
  },
  soc2: {
    name: 'soc2',
    version: '1.0',
    description: 'SOC 2 Type II compliance profile',
    severity_thresholds: { error: 'medium', warn: 'low' },
    rules: {
      sast: {
        enabled: true,
        rulesets: ['owasp-top-10', 'auth-best-practices', 'crypto-best-practices'],
        custom_rules: ['enforce-tls-1.2-minimum', 'require-audit-logging', 'enforce-session-timeout', 'no-hardcoded-credentials'],
      },
      dependencies: { enabled: true, max_cvss_score: 5.0, require_lockfile: true },
      secrets: { enabled: true },
      container: { enabled: true, require_non_root: true },
      iac: { enabled: true },
    },
  },
  'pci-dss': {
    name: 'pci-dss',
    version: '1.0',
    description: 'PCI DSS v4.0 compliance profile',
    severity_thresholds: { error: 'medium', warn: 'low' },
    rules: {
      sast: {
        enabled: true,
        rulesets: ['owasp-top-10', 'crypto-best-practices', 'auth-best-practices'],
        custom_rules: ['enforce-tls-1.2-minimum', 'no-weak-ciphers', 'no-plaintext-pan', 'enforce-input-validation', 'require-audit-logging', 'enforce-session-timeout'],
      },
      dependencies: {
        enabled: true,
        max_cvss_score: 4.0,
        blocked_licenses: ['AGPL-3.0'],
        require_lockfile: true,
      },
      secrets: { enabled: true },
      container: { enabled: true, require_non_root: true, blocked_base_images: ['latest'] },
      iac: { enabled: true },
    },
  },
  hipaa: {
    name: 'hipaa',
    version: '1.0',
    description: 'HIPAA Security Rule compliance profile',
    severity_thresholds: { error: 'medium', warn: 'low' },
    rules: {
      sast: {
        enabled: true,
        rulesets: ['owasp-top-10', 'crypto-best-practices', 'auth-best-practices'],
        custom_rules: ['enforce-tls-1.2-minimum', 'enforce-encryption-at-rest', 'no-phi-in-logs', 'require-audit-logging', 'enforce-access-control', 'enforce-session-timeout'],
      },
      dependencies: { enabled: true, max_cvss_score: 4.0, require_lockfile: true },
      secrets: { enabled: true },
      container: { enabled: true, require_non_root: true },
      iac: { enabled: true },
    },
  },
};

export class ProfileManager {
  private profiles: Record<string, Profile>;
  private activeProfile: string;

  constructor(customProfiles?: Record<string, Profile>) {
    this.profiles = { ...BUILT_IN_PROFILES, ...customProfiles };
    this.activeProfile = 'standard';
  }

  getActive(): Profile {
    return this.profiles[this.activeProfile];
  }

  setActive(name: string): void {
    if (!this.profiles[name]) {
      throw new Error(`Unknown profile: ${name}. Available: ${this.listProfiles().join(', ')}`);
    }
    this.activeProfile = name;
  }

  listProfiles(): string[] {
    return Object.keys(this.profiles);
  }

  getProfile(name: string): Profile | undefined {
    return this.profiles[name];
  }

  loadCustomProfile(projectDir: string): Profile | null {
    const customPath = join(projectDir, '.safeweave', 'profile.yaml');
    if (!existsSync(customPath)) return null;

    const raw = readFileSync(customPath, 'utf-8');
    const parsed = parseYaml(raw) as Record<string, unknown> | null;
    if (!parsed?.extends) return null;

    const base = this.profiles[parsed.extends as string];
    if (!base) throw new Error(`Unknown base profile: ${parsed.extends}`);

    const merged = deepMerge(
      base as unknown as Record<string, unknown>,
      parsed,
    ) as unknown as Profile;
    merged.name = 'custom';
    delete (merged as unknown as Record<string, unknown>).extends;

    this.profiles.custom = merged;
    return merged;
  }
}

function deepMerge(target: Record<string, unknown>, source: Record<string, unknown>): Record<string, unknown> {
  const result: Record<string, unknown> = { ...target };
  for (const key of Object.keys(source)) {
    if (key === 'extends') continue;
    const srcVal = source[key];
    const tgtVal = target[key];
    if (srcVal && tgtVal && typeof srcVal === 'object' && typeof tgtVal === 'object'
        && !Array.isArray(srcVal) && !Array.isArray(tgtVal)) {
      result[key] = deepMerge(tgtVal as Record<string, unknown>, srcVal as Record<string, unknown>);
    } else {
      result[key] = srcVal;
    }
  }
  return result;
}
