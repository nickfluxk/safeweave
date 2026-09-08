import { describe, it, expect } from 'vitest';
import { SEVERITY_WEIGHTS, calculateScore, scoreGrade } from '../score.js';

/**
 * The scoring formula is duplicated across four packages that cannot import one
 * another (mcp-server ships standalone, license-server and dashboard are
 * separate deployables). These tests pin the canonical values so any change
 * fails here and names every mirror that has to change with it.
 *
 * Mirrors:
 *   packages/mcp-server/src/score.ts
 *   packages/license-server/src/services/score.ts
 *   packages/dashboard/src/app/api/public-scan/route.ts
 */
describe('canonical severity weights', () => {
  it('matches the values mirrored in the other three packages', () => {
    expect(SEVERITY_WEIGHTS).toEqual({
      critical: 25,
      high: 15,
      medium: 5,
      low: 0,
      info: 0,
    });
  });

  it('agrees with license-server scoreFromCounts for the same counts', () => {
    // license-server: Math.max(0, 100 - c*25 - h*15 - m*5)
    const cases = [
      { critical: 0, high: 0, medium: 0, expected: 100 },
      { critical: 1, high: 0, medium: 0, expected: 75 },
      { critical: 0, high: 2, medium: 0, expected: 70 },
      { critical: 0, high: 0, medium: 3, expected: 85 },
      { critical: 1, high: 1, medium: 2, expected: 50 },
      { critical: 5, high: 0, medium: 0, expected: 0 },
    ];

    for (const { critical, high, medium, expected } of cases) {
      const findings = [
        ...Array.from({ length: critical }, () => ({ severity: 'critical' })),
        ...Array.from({ length: high }, () => ({ severity: 'high' })),
        ...Array.from({ length: medium }, () => ({ severity: 'medium' })),
      ];
      expect(calculateScore(findings).score).toBe(expected);
      expect(Math.max(0, 100 - critical * 25 - high * 15 - medium * 5)).toBe(expected);
    }
  });

  it('does not let low or info findings move the score', () => {
    const noise = Array.from({ length: 50 }, () => ({ severity: 'low' as const }));
    expect(calculateScore(noise).score).toBe(100);
    expect(calculateScore([{ severity: 'info' }]).score).toBe(100);
  });

  it('uses the same grade thresholds as license-server gradeForScore', () => {
    expect(scoreGrade(100)).toBe('A');
    expect(scoreGrade(90)).toBe('A');
    expect(scoreGrade(89)).toBe('B');
    expect(scoreGrade(80)).toBe('B');
    expect(scoreGrade(79)).toBe('C');
    expect(scoreGrade(70)).toBe('C');
    expect(scoreGrade(69)).toBe('D');
    expect(scoreGrade(60)).toBe('D');
    expect(scoreGrade(59)).toBe('F');
  });
});
