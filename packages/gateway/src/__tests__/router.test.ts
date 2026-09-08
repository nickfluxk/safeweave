import { describe, it, expect, vi, beforeEach } from 'vitest';
import { ScannerClient } from '../router/scanner-client.js';

// Mock fetch globally
const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

describe('ScannerClient', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('sends scan request to correct URL', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ findings: [], metadata: { scanner: 'sast', version: '1.0', duration_ms: 50, files_scanned: 1, timestamp: new Date().toISOString() } }),
    });

    const client = new ScannerClient('http://127.0.0.1:9001');
    await client.scan({ files: [{ path: 'test.ts' }], profile: { name: 'standard', rules: {} }, context: {} });

    expect(mockFetch).toHaveBeenCalledWith(
      'http://127.0.0.1:9001/scan',
      expect.objectContaining({ method: 'POST' })
    );
  });

  it('returns empty findings when scanner is unreachable', async () => {
    mockFetch.mockRejectedValueOnce(new Error('ECONNREFUSED'));

    const client = new ScannerClient('http://127.0.0.1:9001', 'test-scanner');
    const result = await client.scan({ files: [{ path: 'test.ts' }], profile: { name: 'standard', rules: {} }, context: {} });

    expect(result.findings).toEqual([]);
    expect(result.metadata.scanner).toBe('test-scanner');
    expect(result.metadata.warnings).toBeDefined();
    expect(result.metadata.warnings![0]).toContain('test-scanner');
  });

  it('checks scanner health', async () => {
    mockFetch.mockResolvedValueOnce({ ok: true, json: async () => ({ status: 'healthy' }) });

    const client = new ScannerClient('http://127.0.0.1:9001');
    const healthy = await client.isHealthy();

    expect(healthy).toBe(true);
    expect(mockFetch).toHaveBeenCalledWith('http://127.0.0.1:9001/health');
  });
});
