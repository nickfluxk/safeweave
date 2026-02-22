export interface LicenseValidation {
  valid: boolean;
  plan: string | null;
  features: string[];
  expires_at?: string;
}

interface CacheEntry {
  result: LicenseValidation;
  expiry: number;
}

const CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour

const INVALID_RESULT: LicenseValidation = { valid: false, plan: null, features: [] };

export class LicenseClient {
  private cache = new Map<string, CacheEntry>();

  constructor(private serverUrl: string) {}

  async validate(key: string): Promise<LicenseValidation> {
    const cached = this.cache.get(key);
    if (cached && cached.expiry > Date.now()) {
      return cached.result;
    }

    try {
      const res = await fetch(`${this.serverUrl}/api/v1/validate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key }),
        signal: AbortSignal.timeout(5000),
      });

      if (!res.ok) return INVALID_RESULT;

      const result = (await res.json()) as LicenseValidation;

      if (result.valid) {
        this.cache.set(key, { result, expiry: Date.now() + CACHE_TTL_MS });
      }

      return result;
    } catch {
      return INVALID_RESULT;
    }
  }

  async isFeatureAllowed(key: string | undefined, feature: string): Promise<boolean> {
    if (!key) return false;
    const result = await this.validate(key);
    return result.valid && result.features.includes(feature);
  }

  /** Fire-and-forget: report scan usage to the license server */
  reportUsage(key: string | undefined, scanner: string, findings: { severity: string }[], durationMs: number): void {
    if (!key) return;

    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of findings) {
      if (f.severity in counts) {
        counts[f.severity as keyof typeof counts]++;
      }
    }

    fetch(`${this.serverUrl}/api/v1/usage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        key,
        scanner,
        findings_count: findings.length,
        critical_count: counts.critical,
        high_count: counts.high,
        medium_count: counts.medium,
        low_count: counts.low,
        duration_ms: durationMs,
      }),
      signal: AbortSignal.timeout(5000),
    }).catch(() => {
      // Silently ignore reporting failures — don't block scan results
    });
  }
}
