import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parse as parseYaml } from 'yaml';

export interface ScannerConfig {
  enabled: boolean;
  host: string;
  port: number;
}

export interface SafeweaveConfig {
  profile: string;
  gateway: {
    host: string;
    port: number;
  };
  scanners: {
    sast: ScannerConfig;
    deps: ScannerConfig;
    iac: ScannerConfig;
    container: ScannerConfig;
    license: ScannerConfig;
    dast: ScannerConfig;
    secrets: ScannerConfig;
  };
}

export const DEFAULT_CONFIG: SafeweaveConfig = {
  profile: 'standard',
  gateway: {
    host: '0.0.0.0',
    port: 9000,
  },
  scanners: {
    sast: { enabled: true, host: '127.0.0.1', port: 9001 },
    deps: { enabled: true, host: '127.0.0.1', port: 9002 },
    secrets: { enabled: true, host: '127.0.0.1', port: 9003 },
    iac: { enabled: true, host: '127.0.0.1', port: 9004 },
    container: { enabled: true, host: '127.0.0.1', port: 9005 },
    dast: { enabled: true, host: '127.0.0.1', port: 9006 },
    license: { enabled: true, host: '127.0.0.1', port: 9007 },
  },
};

function mergeScanner(defaults: ScannerConfig, overrides?: Partial<ScannerConfig>): ScannerConfig {
  if (!overrides) return { ...defaults };
  return {
    enabled: overrides.enabled ?? defaults.enabled,
    host: overrides.host ?? defaults.host,
    port: overrides.port ?? defaults.port,
  };
}

function applyEnvOverrides(config: SafeweaveConfig): SafeweaveConfig {
  config.gateway.host = process.env.GATEWAY_HOST ?? config.gateway.host;
  config.gateway.port = parseInt(process.env.GATEWAY_PORT || '', 10) || config.gateway.port;

  for (const [name, scanner] of Object.entries(config.scanners)) {
    const envName = name.toUpperCase();
    scanner.host = process.env[`SCANNER_${envName}_HOST`] ?? scanner.host;
    scanner.port = parseInt(process.env[`SCANNER_${envName}_PORT`] || '', 10) || scanner.port;
    if (process.env[`SCANNER_${envName}_ENABLED`] !== undefined) {
      scanner.enabled = process.env[`SCANNER_${envName}_ENABLED`] === 'true';
    }
  }
  return config;
}

export function loadConfig(projectDir: string): SafeweaveConfig {
  const configPath = join(projectDir, '.safeweave', 'config.yaml');
  if (!existsSync(configPath)) {
    return applyEnvOverrides({ ...DEFAULT_CONFIG, scanners: { ...DEFAULT_CONFIG.scanners } });
  }

  try {
    const raw = readFileSync(configPath, 'utf-8');
    const parsed = parseYaml(raw) as Record<string, unknown> | null;

    if (!parsed || typeof parsed !== 'object') {
      return applyEnvOverrides({ ...DEFAULT_CONFIG, scanners: { ...DEFAULT_CONFIG.scanners } });
    }

    const scannerOverrides = (parsed.scanners || {}) as Record<string, Partial<ScannerConfig>>;
    const gatewayOverrides = (parsed.gateway || {}) as Partial<SafeweaveConfig['gateway']>;

    const config: SafeweaveConfig = {
      profile: (parsed.profile as string) || DEFAULT_CONFIG.profile,
      gateway: {
        host: gatewayOverrides.host ?? DEFAULT_CONFIG.gateway.host,
        port: gatewayOverrides.port ?? DEFAULT_CONFIG.gateway.port,
      },
      scanners: {
        sast: mergeScanner(DEFAULT_CONFIG.scanners.sast, scannerOverrides.sast),
        deps: mergeScanner(DEFAULT_CONFIG.scanners.deps, scannerOverrides.deps),
        iac: mergeScanner(DEFAULT_CONFIG.scanners.iac, scannerOverrides.iac),
        container: mergeScanner(DEFAULT_CONFIG.scanners.container, scannerOverrides.container),
        license: mergeScanner(DEFAULT_CONFIG.scanners.license, scannerOverrides.license),
        dast: mergeScanner(DEFAULT_CONFIG.scanners.dast, scannerOverrides.dast),
        secrets: mergeScanner(DEFAULT_CONFIG.scanners.secrets, scannerOverrides.secrets),
      },
    };
    return applyEnvOverrides(config);
  } catch {
    return applyEnvOverrides({ ...DEFAULT_CONFIG, scanners: { ...DEFAULT_CONFIG.scanners } });
  }
}
