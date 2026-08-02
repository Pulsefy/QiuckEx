import { ContractRegistryService, REGISTRY_CACHE_TTL_MS } from '../services/contract-registry';
import AsyncStorage from '@react-native-async-storage/async-storage';

function envelope(data: Record<string, unknown>, overrides: Record<string, unknown> = {}) {
  return {
    network: 'testnet',
    authoritative: true,
    version: 1,
    etag: 'W/"contract-registry-testnet-1"',
    data,
    ...overrides,
  };
}

describe('ContractRegistryService', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    jest.restoreAllMocks();
  });

  it('fetches fresh registry and caches it', async () => {
    const mockBody = envelope({ quickex: { id: 'C123', version: 1 } });
    global.fetch = jest.fn(() =>
      Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(mockBody) })
    ) as jest.Mock;

    const result = await ContractRegistryService.sync('http://localhost');
    expect(result.registry.quickex.id).toBe('C123');
    expect(result.source).toBe('network');
    expect(result.isStale).toBe(false);
    expect(AsyncStorage.setItem).toHaveBeenCalledWith(
      '@contract_registry',
      expect.stringContaining('C123')
    );
  });

  it('falls back to cache on network error', async () => {
    global.fetch = jest.fn(() => Promise.reject(new Error('Network drop')));

    const cachedState = JSON.stringify({
      timestamp: Date.now(),
      data: { quickex: { id: 'C456', version: 1 } }
    });
    (AsyncStorage.getItem as jest.Mock).mockResolvedValue(cachedState);

    const result = await ContractRegistryService.sync('http://localhost');
    expect(result.registry.quickex.id).toBe('C456');
    expect(result.source).toBe('cache');
    expect(result.isStale).toBe(false);
  });

  it('marks cached registry data stale after the cache ttl', async () => {
    const now = 1_800_000_000_000;
    jest.spyOn(Date, 'now').mockReturnValue(now);
    global.fetch = jest.fn(() => Promise.reject(new Error('Network drop')));

    const cachedState = JSON.stringify({
      timestamp: now - REGISTRY_CACHE_TTL_MS - 1,
      data: { quickex: { id: 'C789', version: 1 } }
    });
    (AsyncStorage.getItem as jest.Mock).mockResolvedValue(cachedState);

    const result = await ContractRegistryService.sync('http://localhost');
    expect(result.registry.quickex.id).toBe('C789');
    expect(result.source).toBe('cache');
    expect(result.isStale).toBe(true);
  });

  it('refreshes stale registry data when the network recovers', async () => {
    const now = 1_800_000_000_000;
    jest.spyOn(Date, 'now').mockReturnValue(now);
    const freshBody = envelope({ quickex: { id: 'C999', version: 2 } }, { version: 2 });
    global.fetch = jest.fn()
      .mockRejectedValueOnce(new Error('Network drop'))
      .mockResolvedValueOnce({ ok: true, status: 200, json: () => Promise.resolve(freshBody) });

    const cachedState = JSON.stringify({
      timestamp: now - REGISTRY_CACHE_TTL_MS - 1,
      data: { quickex: { id: 'C789', version: 1 } }
    });
    (AsyncStorage.getItem as jest.Mock).mockResolvedValue(cachedState);

    const staleResult = await ContractRegistryService.sync('http://localhost');
    const refreshedResult = await ContractRegistryService.sync('http://localhost');

    expect(staleResult.isStale).toBe(true);
    expect(refreshedResult.registry.quickex.id).toBe('C999');
    expect(refreshedResult.registry.quickex.version).toBe(2);
    expect(refreshedResult.source).toBe('network');
    expect(refreshedResult.isStale).toBe(false);
  });

  it('throws error if network fails and cache is empty', async () => {
    global.fetch = jest.fn(() => Promise.reject(new Error('Network drop')));
    (AsyncStorage.getItem as jest.Mock).mockResolvedValue(null);

    await expect(ContractRegistryService.sync('http://localhost'))
      .rejects.toThrow('Registry unavailable and no cache found: Network drop');
  });

  it('falls back to cache when the registry route is missing (404)', async () => {
    global.fetch = jest.fn(() =>
      Promise.resolve({ ok: false, status: 404, json: () => Promise.resolve({}) })
    ) as jest.Mock;

    const cachedState = JSON.stringify({
      timestamp: Date.now(),
      data: { quickex: { id: 'C456', version: 1 } }
    });
    (AsyncStorage.getItem as jest.Mock).mockResolvedValue(cachedState);

    const result = await ContractRegistryService.sync('http://localhost');
    expect(result.registry.quickex.id).toBe('C456');
    expect(result.source).toBe('cache');
  });

  it('throws a route-not-found error when the registry route is missing and cache is empty', async () => {
    global.fetch = jest.fn(() =>
      Promise.resolve({ ok: false, status: 404, json: () => Promise.resolve({}) })
    ) as jest.Mock;
    (AsyncStorage.getItem as jest.Mock).mockResolvedValue(null);

    await expect(ContractRegistryService.sync('http://localhost'))
      .rejects.toThrow('Contract registry route not found on backend');
  });

  it('falls back to cache when the response payload is malformed', async () => {
    global.fetch = jest.fn(() =>
      Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({ quickex: { id: 'flat-shape' } }) })
    ) as jest.Mock;

    const cachedState = JSON.stringify({
      timestamp: Date.now(),
      data: { quickex: { id: 'C456', version: 1 } }
    });
    (AsyncStorage.getItem as jest.Mock).mockResolvedValue(cachedState);

    const result = await ContractRegistryService.sync('http://localhost');
    expect(result.registry.quickex.id).toBe('C456');
    expect(result.source).toBe('cache');
  });

  it('throws a malformed-payload error when the response has no data field and cache is empty', async () => {
    global.fetch = jest.fn(() =>
      Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({ quickex: { id: 'flat-shape' } }) })
    ) as jest.Mock;
    (AsyncStorage.getItem as jest.Mock).mockResolvedValue(null);

    await expect(ContractRegistryService.sync('http://localhost'))
      .rejects.toThrow('Registry unavailable and no cache found: Contract registry response payload is malformed');
  });
});
