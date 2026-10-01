import AsyncStorage from '@react-native-async-storage/async-storage';
import {
  fetchRuntimeConfigBootstrap,
  sanitizeRuntimeConfig,
  getCachedRuntimeConfig,
  setCachedRuntimeConfig,
  clearRuntimeConfigCache,
  DEFAULT_FALLBACK_CONFIGS,
} from '../services/runtime-config';
import { ContractRegistryService } from '../services/contract-registry';
import type { PartialRuntimeConfigResponse } from '../types/runtime-config';

// Mock AsyncStorage
jest.mock('@react-native-async-storage/async-storage', () => ({
  getItem: jest.fn(),
  setItem: jest.fn(),
  removeItem: jest.fn(),
  clear: jest.fn(),
}));

describe('Runtime Config Bootstrap Service', () => {
  const originalFetch = global.fetch;

  beforeEach(() => {
    jest.clearAllMocks();
    ContractRegistryService.clearMemoryCache();
  });

  afterEach(() => {
    global.fetch = originalFetch;
  });

  describe('sanitizeRuntimeConfig & Fallback Handling', () => {
    it('uses fallback config when input payload is completely empty or null', () => {
      const fallback = DEFAULT_FALLBACK_CONFIGS.testnet;
      const sanitized = sanitizeRuntimeConfig(null, 'testnet');

      expect(sanitized.environment).toBe('testnet');
      expect(sanitized.network.network).toBe(fallback.network.network);
      expect(sanitized.network.horizonUrl).toBe(fallback.network.horizonUrl);
      expect(sanitized.network.sorobanRpcUrl).toBe(fallback.network.sorobanRpcUrl);
      expect(sanitized.network.networkPassphrase).toBe(fallback.network.networkPassphrase);
      expect(sanitized.contracts.length).toBeGreaterThan(0);
      expect(sanitized.contracts.find((c) => c.contractId === 'token-bridge')).toBeDefined();
    });

    it('gracefully handles partially missing payload fields without throwing', () => {
      const partialPayload: PartialRuntimeConfigResponse = {
        environment: 'staging',
        contracts: [
          {
            contractId: 'custom-contract',
            address: 'CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM',
            deployedAt: '2026-09-01T00:00:00Z',
            version: '1.2.0',
          },
        ],
      };

      const sanitized = sanitizeRuntimeConfig(partialPayload, 'staging');

      expect(sanitized.environment).toBe('staging');
      // Network should be safely populated from staging fallback
      expect(sanitized.network.network).toBe('testnet');
      expect(sanitized.network.horizonUrl).toBe('https://horizon-testnet.stellar.org');
      expect(sanitized.network.sorobanRpcUrl).toBe('https://soroban-testnet.stellar.org');
      // Contracts should include custom-contract from payload
      expect(sanitized.contracts.some((c) => c.contractId === 'custom-contract')).toBe(true);
      // Feature flags should safely default to fallback/empty
      expect(sanitized.featureFlags).toBeDefined();
      expect(sanitized.mobileVersionPolicy.minAppVersion).toBe('1.0.0');
    });

    it('merges backend-provided contracts with fallback contracts so critical contracts are never missing', () => {
      const partialPayload: PartialRuntimeConfigResponse = {
        environment: 'testnet',
        contracts: [
          {
            contractId: 'token-bridge',
            address: 'C_OVERRIDDEN_BACKEND_ADDRESS',
            version: '2.0.0',
          },
        ],
      };

      const sanitized = sanitizeRuntimeConfig(partialPayload, 'testnet');
      const bridge = sanitized.contracts.find((c) => c.contractId === 'token-bridge');
      expect(bridge?.address).toBe('C_OVERRIDDEN_BACKEND_ADDRESS');
      expect(bridge?.version).toBe('2.0.0');

      // Native asset contract from fallback should still be present
      const nativeAsset = sanitized.contracts.find((c) => c.contractId === 'native-asset');
      expect(nativeAsset).toBeDefined();
    });

    it('populates preview metadata for branch-preview with scope', () => {
      const sanitized = sanitizeRuntimeConfig(
        {
          environment: 'branch-preview',
          preview: {
            scope: 'pr-456',
            branch: 'feat/preview-test',
            commitSha: 'abcdef12',
          },
        },
        'branch-preview',
        'pr-456',
      );

      expect(sanitized.environment).toBe('branch-preview');
      expect(sanitized.preview?.scope).toBe('pr-456');
      expect(sanitized.preview?.branch).toBe('feat/preview-test');
      expect(sanitized.preview?.commitSha).toBe('abcdef12');
    });

    it('falls back preview metadata when backend omits preview block on branch-preview', () => {
      const sanitized = sanitizeRuntimeConfig({}, 'branch-preview', 'pr-999');

      expect(sanitized.environment).toBe('branch-preview');
      expect(sanitized.preview?.scope).toBe('pr-999');
      expect(sanitized.preview?.branch).toBe('pr-999');
    });
  });

  describe('AsyncStorage Caching & ETag Validation', () => {
    it('saves runtime config and etag to cache', async () => {
      const config = DEFAULT_FALLBACK_CONFIGS.testnet;
      await setCachedRuntimeConfig('testnet', config, '"etag-123"');

      expect(AsyncStorage.setItem).toHaveBeenCalledWith(
        '@quickex/runtime_config_testnet',
        expect.stringContaining('etag-123'),
      );
    });

    it('reads cached runtime config and respects expiration', async () => {
      const config = DEFAULT_FALLBACK_CONFIGS.testnet;
      (AsyncStorage.getItem as jest.Mock).mockResolvedValueOnce(
        JSON.stringify({
          config,
          etag: '"etag-abc"',
          cachedAt: Date.now(), // fresh
        }),
      );

      const cached = await getCachedRuntimeConfig('testnet');
      expect(cached).not.toBeNull();
      expect(cached?.environment).toBe('testnet');
    });

    it('returns null when cached config has expired past TTL', async () => {
      const config = DEFAULT_FALLBACK_CONFIGS.testnet;
      const expiredTime = Date.now() - 25 * 60 * 60 * 1000; // 25 hours old (> 24h TTL)
      (AsyncStorage.getItem as jest.Mock).mockResolvedValueOnce(
        JSON.stringify({
          config,
          etag: '"etag-old"',
          cachedAt: expiredTime,
        }),
      );

      const cached = await getCachedRuntimeConfig('testnet');
      expect(cached).toBeNull();
    });

    it('clears runtime config cache on demand', async () => {
      await clearRuntimeConfigCache('staging');
      expect(AsyncStorage.removeItem).toHaveBeenCalledWith('@quickex/runtime_config_staging');
    });
  });

  describe('fetchRuntimeConfigBootstrap', () => {
    it('sends X-Preview-Scope header when previewScope is specified', async () => {
      let capturedHeaders: Record<string, string> = {};
      global.fetch = jest.fn().mockImplementation((_url, init) => {
        capturedHeaders = init?.headers ?? {};
        return Promise.resolve({
          ok: true,
          status: 200,
          headers: { get: () => '"etag-pr-42"' },
          json: async () => ({
            environment: 'branch-preview',
            network: {
              network: 'testnet',
              horizonUrl: 'https://preview-horizon.quickex.org',
              sorobanRpcUrl: 'https://preview-soroban.quickex.org',
              networkPassphrase: 'Test SDF Network ; September 2015',
            },
            preview: {
              scope: 'pr-42',
              branch: 'feat/mobile-test',
            },
          }),
        });
      });

      const result = await fetchRuntimeConfigBootstrap(
        'https://preview-api.quickex.org',
        'branch-preview',
        { previewScope: 'pr-42', skipCache: true },
      );

      expect(capturedHeaders['X-Preview-Scope']).toBe('pr-42');
      expect(result.source).toBe('network');
      expect(result.config.preview?.scope).toBe('pr-42');
      expect(result.config.network.horizonUrl).toBe('https://preview-horizon.quickex.org');
    });

    it('handles HTTP 304 Not Modified using cached payload and returns source=cache', async () => {
      const cachedConfig = DEFAULT_FALLBACK_CONFIGS.testnet;
      (AsyncStorage.getItem as jest.Mock).mockResolvedValueOnce(
        JSON.stringify({
          config: cachedConfig,
          etag: '"304-etag"',
          cachedAt: Date.now(),
        }),
      );

      let capturedIfNoneMatch: string | undefined;
      global.fetch = jest.fn().mockImplementation((_url, init) => {
        capturedIfNoneMatch = init?.headers?.['If-None-Match'];
        return Promise.resolve({
          ok: false,
          status: 304,
          headers: { get: () => '"304-etag"' },
        });
      });

      const result = await fetchRuntimeConfigBootstrap(
        'https://testnet-api.quickex.org',
        'testnet',
      );

      expect(capturedIfNoneMatch).toBe('"304-etag"');
      expect(result.source).toBe('cache');
      expect(result.config.environment).toBe('testnet');
    });

    it('falls back gracefully to DEFAULT_FALLBACK_CONFIGS when network request fails', async () => {
      (AsyncStorage.getItem as jest.Mock).mockResolvedValueOnce(null);
      global.fetch = jest.fn().mockRejectedValue(new Error('Network connection offline'));

      const result = await fetchRuntimeConfigBootstrap(
        'https://api.quickex.org',
        'production',
      );

      expect(result.source).toBe('fallback');
      expect(result.config.environment).toBe('production');
      expect(result.config.network.network).toBe('public');
    });
  });

  describe('Contract Registry Integration', () => {
    it('populates contract registry dynamically from bootstrap contracts', async () => {
      const testPassphrase = 'Test SDF Network ; September 2015';
      const bootstrapContracts = [
        {
          contractId: 'token-bridge',
          address: 'CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM',
          deployedAt: '2026-09-25T00:00:00Z',
          version: '3.0.0',
        },
        {
          contractId: 'dex-router',
          address: 'CBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB3KM',
          version: '1.0.0',
        },
      ];

      await ContractRegistryService.populateFromBootstrap(bootstrapContracts, testPassphrase);

      const bridgeAddress = await ContractRegistryService.getContract('token-bridge');
      expect(bridgeAddress).toBe('CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM');

      const bridgeEntry = await ContractRegistryService.getContractEntry('token-bridge');
      expect(bridgeEntry?.id).toBe('CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM');
      expect(bridgeEntry?.schemaVersion).toBe('3.0.0');
      expect(bridgeEntry?.networkPassphrase).toBe(testPassphrase);

      const dexAddress = await ContractRegistryService.getContract('dex-router');
      expect(dexAddress).toBe('CBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB3KM');
    });
  });
});
