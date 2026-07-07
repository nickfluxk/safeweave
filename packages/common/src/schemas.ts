import type { ValidationResult, Severity } from './types.js';

const VALID_SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

export function validateFinding(input: unknown): ValidationResult {
  const errors: string[] = [];
  if (!input || typeof input !== 'object') {
    return { valid: false, errors: ['Finding must be an object'] };
  }

  const obj = input as Record<string, unknown>;

  if (typeof obj.id !== 'string' || obj.id.length === 0) {
    errors.push('id is required and must be a non-empty string');
  }
  if (!VALID_SEVERITIES.includes(obj.severity as Severity)) {
    errors.push(`severity must be one of: ${VALID_SEVERITIES.join(', ')}`);
  }
  if (typeof obj.title !== 'string' || obj.title.length === 0) {
    errors.push('title is required and must be a non-empty string');
  }
  if (typeof obj.description !== 'string' || obj.description.length === 0) {
    errors.push('description is required and must be a non-empty string');
  }
  if (typeof obj.file !== 'string' || obj.file.length === 0) {
    errors.push('file is required and must be a non-empty string');
  }
  if (typeof obj.remediation !== 'string' || obj.remediation.length === 0) {
    errors.push('remediation is required and must be a non-empty string');
  }

  return { valid: errors.length === 0, errors };
}

export function validateScanRequest(input: unknown): ValidationResult {
  const errors: string[] = [];
  if (!input || typeof input !== 'object') {
    return { valid: false, errors: ['ScanRequest must be an object'] };
  }

  const obj = input as Record<string, unknown>;

  if (!Array.isArray(obj.files) || obj.files.length === 0) {
    errors.push('files must be a non-empty array');
  }
  if (!obj.profile || typeof obj.profile !== 'object') {
    errors.push('profile is required and must be an object');
  }
  if (!obj.context || typeof obj.context !== 'object') {
    errors.push('context is required and must be an object');
  }

  return { valid: errors.length === 0, errors };
}
