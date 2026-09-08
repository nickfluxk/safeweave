import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { LicenseClient } from '../license.js';

describe('LicenseClient', () => {
  let client: LicenseClient;

  beforeEach(() => {
    client = new LicenseClient('http://localhost:4000');
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('returns allowed features for a valid key', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      new Response(JSON.stringify({
        valid: true,
        plan: 'pro',
        features: ['deps', 'iac', 'container', 'dast', 'license'],
      }), { status: 200 }),
    );

    const result = await client.validate('sw_pro_abc123');
    expect(result.valid).toBe(true);
    expect(result.features).toContain('deps');
  });

  it('returns invalid for a bad key', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      new Response(JSON.stringify({ valid: false, plan: null, features: [] }), { status: 200 }),
    );

    const result = await client.validate('bad_key');
    expect(result.valid).toBe(false);
    expect(result.features).toEqual([]);
  });

  it('returns invalid when license server is unreachable (fail-closed)', async () => {
    vi.spyOn(globalThis, 'fetch').mockRejectedValueOnce(new Error('ECONNREFUSED'));

    const result = await client.validate('sw_pro_abc123');
    expect(result.valid).toBe(false);
    expect(result.features).toEqual([]);
  });

  it('caches valid responses and reuses them', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({
        valid: true,
        plan: 'pro',
        features: ['deps'],
      }), { status: 200 }),
    );

    await client.validate('sw_pro_abc123');
    await client.validate('sw_pro_abc123');

    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });

  it('isFeatureAllowed returns true for gated feature with valid license', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      new Response(JSON.stringify({
        valid: true,
        plan: 'pro',
        features: ['deps', 'iac'],
      }), { status: 200 }),
    );

    const allowed = await client.isFeatureAllowed('sw_pro_abc123', 'deps');
    expect(allowed).toBe(true);
  });

  it('isFeatureAllowed returns false without license key', async () => {
    const allowed = await client.isFeatureAllowed(undefined, 'deps');
    expect(allowed).toBe(false);
  });
});
