import { describe, it, expect } from 'vitest';
import { validateFinding, validateScanRequest } from '../schemas.js';

describe('validateFinding', () => {
  it('accepts a valid finding', () => {
    const finding = {
      id: 'SAST-001',
      severity: 'high',
      title: 'SQL Injection',
      description: 'User input used in SQL query without sanitization',
      file: 'src/db.ts',
      line: 42,
      cwe: 'CWE-89',
      compliance: ['owasp-a03'],
      remediation: 'Use parameterized queries',
    };
    expect(validateFinding(finding)).toEqual({ valid: true, errors: [] });
  });

  it('rejects a finding with invalid severity', () => {
    const finding = {
      id: 'SAST-001',
      severity: 'extreme',
      title: 'Bad thing',
      description: 'Something bad',
      file: 'src/bad.ts',
      remediation: 'Fix it',
    };
    const result = validateFinding(finding);
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
  });

  it('rejects a finding missing required fields', () => {
    const finding = { id: 'SAST-001' };
    const result = validateFinding(finding);
    expect(result.valid).toBe(false);
  });
});

describe('validateScanRequest', () => {
  it('accepts a valid scan request', () => {
    const request = {
      files: [{ path: 'src/index.ts', content: 'console.log("hi")' }],
      profile: { name: 'standard', rules: {} },
      context: { language: 'typescript' },
    };
    expect(validateScanRequest(request)).toEqual({ valid: true, errors: [] });
  });

  it('rejects a scan request with no files', () => {
    const request = {
      files: [],
      profile: { name: 'standard', rules: {} },
      context: { language: 'typescript' },
    };
    const result = validateScanRequest(request);
    expect(result.valid).toBe(false);
  });
});
