import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { fetchBootstrapConfig } from './bootstrap.service';
import { FALLBACK_BOOTSTRAP_CONFIG } from '../config/bootstrap.config';

describe('Bootstrap Service - fetchBootstrapConfig', () => {
  const originalFetch = global.fetch;

  beforeEach(() => {
    global.fetch = vi.fn();
    
    vi.stubEnv('VITE_API_BASE_URL', 'http://localhost:mock');
  });

  afterEach(() => {
    global.fetch = originalFetch;
    vi.unstubAllEnvs();
  });

  it('should return fully merged config on a successful response', async () => {
    const mockBackendPayload = {
      network: { environment: 'preview', rpcUrl: 'https://preview-rpc.local' },
      contracts: { registryId: 'C_MOCK_REGISTRY' },
      backendMetadata: { version: '1.5.0-preview' },
    };

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => mockBackendPayload,
    });

    const config = await fetchBootstrapConfig();

    expect(global.fetch).toHaveBeenCalledWith(
      'http://localhost:mock/v1/network/bootstrap',
      expect.any(Object)
    );

    expect(config.network.environment).toBe('preview');
    expect(config.network.rpcUrl).toBe('https://preview-rpc.local');
    expect(config.contracts.registryId).toBe('C_MOCK_REGISTRY');
    expect(config.backendMetadata.version).toBe('1.5.0-preview');
    expect(config.network.horizonUrl).toBe(FALLBACK_BOOTSTRAP_CONFIG.network.horizonUrl);
    expect(config.backendMetadata.featureFlags).toEqual(FALLBACK_BOOTSTRAP_CONFIG.backendMetadata.featureFlags);
  });

  it('should return the fallback config on HTTP errors (e.g., 500 Internal Server Error)', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 500,
    });

    const consoleSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

    const config = await fetchBootstrapConfig();

    expect(config).toEqual(FALLBACK_BOOTSTRAP_CONFIG);
    expect(consoleSpy).toHaveBeenCalledWith(
      'Failed to load backend bootstrap. Using fallback configuration.',
      expect.any(Error)
    );

    consoleSpy.mockRestore();
  });

  it('should return the fallback config on complete network failures', async () => {
    global.fetch = vi.fn().mockRejectedValue(new Error('Network connection lost'));

    const consoleSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

    const config = await fetchBootstrapConfig();

    expect(config).toEqual(FALLBACK_BOOTSTRAP_CONFIG);
    expect(consoleSpy).toHaveBeenCalledWith(
      'Failed to load backend bootstrap. Using fallback configuration.',
      expect.any(Error)
    );

    consoleSpy.mockRestore();
  });

  it('should handle completely empty backend payloads gracefully', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({}),
    });

    const config = await fetchBootstrapConfig();

    expect(config).toEqual(FALLBACK_BOOTSTRAP_CONFIG);
  });
});