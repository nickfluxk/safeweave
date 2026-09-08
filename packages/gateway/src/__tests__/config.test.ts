import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { loadConfig, DEFAULT_CONFIG } from '../config.js';
import { mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';

describe('loadConfig', () => {
  it('returns default config when no config file exists', () => {
    const config = loadConfig('/nonexistent/path');
    expect(config.profile).toBe('standard');
    expect(config.scanners.sast.enabled).toBe(true);
    expect(config.scanners.sast.port).toBe(9001);
  });

  it('has correct default ports for all scanners', () => {
    const config = DEFAULT_CONFIG;
    expect(config.scanners.sast.port).toBe(9001);
    expect(config.scanners.deps.port).toBe(9002);
    expect(config.scanners.secrets.port).toBe(9003);
  });

  describe('YAML parsing', () => {
    let tmpDir: string;

    beforeEach(() => {
      tmpDir = mkdtempSync(join(tmpdir(), 'sw-config-'));
      mkdirSync(join(tmpDir, '.safeweave'), { recursive: true });
    });

    afterEach(() => {
      rmSync(tmpDir, { recursive: true, force: true });
    });

    it('reads licenseKey from config file', () => {
      writeFileSync(
        join(tmpDir, '.safeweave', 'config.yaml'),
        'profile: standard\nlicenseKey: sw_pro_testkey123\n',
      );
      const config = loadConfig(tmpDir);
      expect(config.licenseKey).toBe('sw_pro_testkey123');
    });

    it('reads profile from config file', () => {
      writeFileSync(
        join(tmpDir, '.safeweave', 'config.yaml'),
        'profile: hardened\n',
      );
      const config = loadConfig(tmpDir);
      expect(config.profile).toBe('hardened');
    });

    it('reads scanner port overrides', () => {
      writeFileSync(
        join(tmpDir, '.safeweave', 'config.yaml'),
        'scanners:\n  sast:\n    port: 8001\n    enabled: true\n',
      );
      const config = loadConfig(tmpDir);
      expect(config.scanners.sast.port).toBe(8001);
      expect(config.scanners.deps.port).toBe(9002); // default preserved
    });

    it('handles malformed YAML gracefully', () => {
      writeFileSync(join(tmpDir, '.safeweave', 'config.yaml'), '{{invalid yaml');
      const config = loadConfig(tmpDir);
      expect(config.profile).toBe('standard');
    });
  });

  describe('env var overrides', () => {
    const envVarsToClean: string[] = [];

    function setEnv(key: string, value: string) {
      envVarsToClean.push(key);
      process.env[key] = value;
    }

    afterEach(() => {
      for (const key of envVarsToClean) {
        delete process.env[key];
      }
      envVarsToClean.length = 0;
    });

    it('overrides scanner host from env var', () => {
      setEnv('SCANNER_SAST_HOST', 'sast.railway.internal');
      const config = loadConfig('/nonexistent/path');
      expect(config.scanners.sast.host).toBe('sast.railway.internal');
    });

    it('overrides scanner port from env var', () => {
      setEnv('SCANNER_DEPS_PORT', '8888');
      const config = loadConfig('/nonexistent/path');
      expect(config.scanners.deps.port).toBe(8888);
    });

    it('overrides scanner enabled from env var', () => {
      setEnv('SCANNER_IAC_ENABLED', 'true');
      const config = loadConfig('/nonexistent/path');
      expect(config.scanners.iac.enabled).toBe(true);
    });

    it('disables scanner via env var', () => {
      setEnv('SCANNER_SAST_ENABLED', 'false');
      const config = loadConfig('/nonexistent/path');
      expect(config.scanners.sast.enabled).toBe(false);
    });

    it('overrides gateway host and port from env vars', () => {
      setEnv('GATEWAY_HOST', '0.0.0.0');
      setEnv('GATEWAY_PORT', '8080');
      const config = loadConfig('/nonexistent/path');
      expect(config.gateway.host).toBe('0.0.0.0');
      expect(config.gateway.port).toBe(8080);
    });

    it('overrides licenseKey from env var', () => {
      setEnv('SAFEWEAVE_LICENSE_KEY', 'sw_pro_envkey');
      const config = loadConfig('/nonexistent/path');
      expect(config.licenseKey).toBe('sw_pro_envkey');
    });

    it('env vars take precedence over YAML config', () => {
      const tmpDir = mkdtempSync(join(tmpdir(), 'sw-config-env-'));
      mkdirSync(join(tmpDir, '.safeweave'), { recursive: true });
      writeFileSync(
        join(tmpDir, '.safeweave', 'config.yaml'),
        'scanners:\n  sast:\n    host: yaml-host\n    port: 1111\n',
      );

      setEnv('SCANNER_SAST_HOST', 'env-host');
      setEnv('SCANNER_SAST_PORT', '2222');

      const config = loadConfig(tmpDir);
      expect(config.scanners.sast.host).toBe('env-host');
      expect(config.scanners.sast.port).toBe(2222);

      rmSync(tmpDir, { recursive: true, force: true });
    });
  });
});
