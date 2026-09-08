export interface ScoreResult {
  score: number;
  status: string;
  breakdown: Record<string, number>;
}

/**
 * Canonical severity weights. These same numbers are mirrored in three other
 * places that cannot import this package, and all four MUST stay in step —
 * otherwise the same findings score differently depending on which surface the
 * user looks at:
 *
 *   - packages/mcp-server/src/score.ts        (ships standalone via npx, no workspace deps)
 *   - packages/license-server/src/services/score.ts  (separate deployable)
 *   - packages/dashboard/src/app/api/public-scan/route.ts
 *
 * `score-weights.test.ts` pins these values so a change here fails loudly and
 * names the mirrors. Note `low` and `info` are weighted 0: low-severity
 * findings do not move the score or the grade.
 */
export const SEVERITY_WEIGHTS: Record<string, number> = {
  critical: 25,
  high: 15,
  medium: 5,
  low: 0,
  info: 0,
};

/**
 * Compute the SafeWeave security score (0-100) from a set of findings.
 * Used by the gateway and the CLI score card; mirrored by the surfaces listed
 * on SEVERITY_WEIGHTS. Structurally typed on `severity` so any finding shape works.
 */
export function calculateScore(findings: Array<{ severity: string }>): ScoreResult {
  if (findings.length === 0) {
    return { score: 100, status: 'no_findings', breakdown: {} };
  }

  const weights = SEVERITY_WEIGHTS;
  let deductions = 0;
  const breakdown: Record<string, number> = {};

  for (const f of findings) {
    deductions += weights[f.severity] || 0;
    breakdown[f.severity] = (breakdown[f.severity] || 0) + 1;
  }

  const score = Math.max(0, 100 - deductions);
  const status = score >= 80 ? 'good' : score >= 50 ? 'needs_attention' : 'critical';

  return { score, status, breakdown };
}

/** Map a 0-100 score to a letter grade. */
export function scoreGrade(score: number): 'A' | 'B' | 'C' | 'D' | 'F' {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  return 'F';
}
