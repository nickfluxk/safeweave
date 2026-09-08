import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { ProfileManager } from '../profiles/index.js';
import { mkdirSync, writeFileSync, rmSync, mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

describe('ProfileManager', () => {
  it('loads the standard profile by default', () => {
    const manager = new ProfileManager();
    const profile = manager.getActive();
    expect(profile.name).toBe('standard');
    expect(profile.severity_thresholds.error).toBe('high');
  });

  it('switches to hardened profile', () => {
    const manager = new ProfileManager();
    manager.setActive('hardened');
    const profile = manager.getActive();
    expect(profile.name).toBe('hardened');
    expect(profile.severity_thresholds.error).toBe('medium');
  });

  it('lists all 6 available profiles', () => {
    const manager = new ProfileManager();
    const profiles = manager.listProfiles();
    expect(profiles).toContain('standard');
    expect(profiles).toContain('hardened');
    expect(profiles).toContain('owasp');
    expect(profiles).toContain('soc2');
    expect(profiles).toContain('pci-dss');
    expect(profiles).toContain('hipaa');
    expect(profiles).toHaveLength(6);
  });

  it('switches to compliance profiles', () => {
    const manager = new ProfileManager();
    for (const name of ['owasp', 'soc2', 'pci-dss', 'hipaa']) {
      manager.setActive(name);
      const profile = manager.getActive();
      expect(profile.name).toBe(name);
      expect(profile.rules.sast?.enabled).toBe(true);
    }
  });

  it('throws on unknown profile', () => {
    const manager = new ProfileManager();
    expect(() => manager.setActive('nonexistent')).toThrow();
  });

  describe('custom profile extends', () => {
    let tmpDir: string;

    beforeEach(() => {
      tmpDir = mkdtempSync(join(tmpdir(), 'sw-profile-'));
      mkdirSync(join(tmpDir, '.safeweave'), { recursive: true });
    });

    afterEach(() => {
      rmSync(tmpDir, { recursive: true, force: true });
    });

    it('loads custom profile extending owasp', () => {
      writeFileSync(
        join(tmpDir, '.safeweave', 'profile.yaml'),
        'extends: owasp\nseverity_thresholds:\n  error: critical\n',
      );
      const manager = new ProfileManager();
      const profile = manager.loadCustomProfile(tmpDir);

      expect(profile).not.toBeNull();
      expect(profile!.name).toBe('custom');
      expect(profile!.severity_thresholds.error).toBe('critical');
      expect(profile!.severity_thresholds.warn).toBe('medium'); // inherited from owasp
    });

    it('returns null when no custom profile exists', () => {
      const manager = new ProfileManager();
      const profile = manager.loadCustomProfile(tmpDir);
      expect(profile).toBeNull();
    });

    it('returns null when profile has no extends field', () => {
      writeFileSync(
        join(tmpDir, '.safeweave', 'profile.yaml'),
        'severity_thresholds:\n  error: critical\n',
      );
      const manager = new ProfileManager();
      const profile = manager.loadCustomProfile(tmpDir);
      expect(profile).toBeNull();
    });

    it('throws on unknown base profile', () => {
      writeFileSync(
        join(tmpDir, '.safeweave', 'profile.yaml'),
        'extends: nonexistent\n',
      );
      const manager = new ProfileManager();
      expect(() => manager.loadCustomProfile(tmpDir)).toThrow('Unknown base profile: nonexistent');
    });

    it('deep merges rules from custom profile', () => {
      writeFileSync(
        join(tmpDir, '.safeweave', 'profile.yaml'),
        'extends: standard\nrules:\n  sast:\n    custom_rules:\n      - ./my-rules/\n',
      );
      const manager = new ProfileManager();
      const profile = manager.loadCustomProfile(tmpDir);

      expect(profile!.rules.sast?.enabled).toBe(true); // inherited
      expect(profile!.rules.sast?.custom_rules).toEqual(['./my-rules/']);
    });
  });
});
