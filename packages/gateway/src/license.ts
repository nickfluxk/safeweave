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

  /** `repo` (optional) attributes reported scans to a repository for per-repo scores. */
  constructor(private serverUrl: string, private repo?: string) {}

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

  /** Fire-and-forget: report scan usage and individual findings to the license server */
  /**
   * @param repo Per-call repository attribution, overriding the instance
   *   default. The HTTP bridge is a SINGLE client shared by every caller, so
   *   constructor-level attribution is structurally wrong there: whatever slug
   *   it held would be applied to all tenants' scans, and because the dashboard
   *   reads scans back with DISTINCT ON (repo), each repo would overwrite the
   *   previous one instead of being scored separately.
   */
  reportUsage(key: string | undefined, scanner: string, findings: { severity: string; id?: string; title?: string; file?: string; line?: number; cwe?: string; compliance?: string[] }[], durationMs: number, repo?: string): void {
    if (!key) return;

    // Use /report endpoint which stores both aggregate counts AND individual findings
    fetch(`${this.serverUrl}/api/v1/report`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${key}`,
      },
      body: JSON.stringify({
        findings: findings.map(f => ({
          id: f.id,
          severity: f.severity,
          title: f.title,
          file: f.file,
          line: f.line,
          cwe: f.cwe,
          compliance: f.compliance,
        })),
        metadata: {
          scanner,
          duration_ms: durationMs,
          files_scanned: 0,
          timestamp: new Date().toISOString(),
          repo: repo ?? this.repo,
        },
      }),
      signal: AbortSignal.timeout(10000),
    }).then(async (res) => {
      if (!res.ok) {
        const body = await res.text().catch(() => '');
        console.error(`SafeWeave: report failed (${res.status}): ${body}`);
      } else {
        console.log(`SafeWeave: reported ${findings.length} findings for scanner=${scanner}`);
      }
    }).catch((err) => {
      console.error(`SafeWeave: report request failed: ${err}`);
    });
  }
}
