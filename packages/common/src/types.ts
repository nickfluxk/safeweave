export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface FileTarget {
  path: string;
  content?: string;
}

export interface ProfileRules {
  name: string;
  rules: Record<string, unknown>;
}

export interface ProjectContext {
  language?: string;
  framework?: string;
  rootDir?: string;
  target_url?: string;
}

export interface Finding {
  id: string;
  severity: Severity;
  title: string;
  description: string;
  file: string;
  line?: number;
  cwe?: string;
  compliance?: string[];
  remediation: string;
  code_snippet?: string;
  fix_snippet?: string;
}

export interface ScanRequest {
  files: FileTarget[];
  profile: ProfileRules;
  context: ProjectContext;
}

export interface ScanResult {
  findings: Finding[];
  metadata: ScanMetadata;
}

export interface ScanMetadata {
  scanner: string;
  version: string;
  duration_ms: number;
  files_scanned: number;
  timestamp: string;
  warnings?: string[];
}

export interface ValidationResult {
  valid: boolean;
  errors: string[];
}

export interface Profile {
  name: string;
  version: string;
  description: string;
  severity_thresholds: {
    error: Severity;
    warn: Severity;
  };
  rules: ProfileRuleConfig;
}

export interface ProfileRuleConfig {
  sast?: ScannerRuleConfig;
  dependencies?: DependencyRuleConfig;
  iac?: ScannerRuleConfig;
  container?: ContainerRuleConfig;
  dast?: DastRuleConfig;
  secrets?: ScannerRuleConfig;
}

export interface ScannerRuleConfig {
  enabled: boolean;
  rulesets?: string[];
  custom_rules?: string[];
}

export interface DependencyRuleConfig {
  enabled: boolean;
  max_cvss_score?: number;
  blocked_licenses?: string[];
  require_lockfile?: boolean;
}

export interface ContainerRuleConfig {
  enabled: boolean;
  max_cvss_score?: number;
  require_non_root?: boolean;
  blocked_base_images?: string[];
}

export interface DastRuleConfig {
  enabled: boolean;
  checks?: string[];
}
