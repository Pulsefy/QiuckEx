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

function responseHeaders(values: Record<string, string> = {}) {
  const lower: Record<string, string> = {};
  for (const [key, value] of Object.entries(values)) lower[key.toLowerCase()] = value;
  return {
    get: (name: string) => lower[name.toLowerCase()] ?? null,
  };
}

describe('ContractRegistryService', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    jest.restoreAllMocks();
  });


  it('GETs the backend registry at /contracts/registry (no /api prefix) and parses network result', async () => {
    const mockBody = envelope({
      quickex: {
        id: 'C321',
        wasmHash: 'abc',
        version: 1,
        schemaVersion: '1.0.0',
        schemaCompatibility: { min: '1.0.0', max: '1.0.0' },
        networkPassphrase: 'Test SDF Network ; September 2015',
        updatedAt: '2026-01-01T00:00:00.000Z',
      },
    });
    const fetchMock = jest.fn(() =>
      Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(mockBody) })
    ) as jest.Mock;
    global.fetch = fetchMock;

    const result = await ContractRegistryService.sync('http://localhost:3000');

    expect(fetchMock).toHaveBeenCalledWith('http://localhost:3000/contracts/registry', { headers: {} });
    expect(fetchMock).not.toHaveBeenCalledWith(expect.stringContaining('/api/contracts/registry'));
    expect(result.source).toBe('network');
    expect(result.isStale).toBe(false);
    expect(result.registry.quickex.id).toBe('C321');
    expect(result.fetchedAt).toEqual(expect.any(Number));
  });

  it('fetches fresh registry and caches it', async () => {
    const mockBody = envelope({ quickex: { id: 'C123', version: 1 } });
    global.fetch = jest.fn(() =>
      Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(mockBody) })
    ) as jest.Mock;

    const result = await ContractRegistryService.sync('http://localhost');
    expect(global.fetch).toHaveBeenCalledWith('http://localhost/contracts/registry', { headers: {} });
    expect(result.registry.quickex.id).toBe('C123');
    expect(result.source).toBe('network');
    expect(result.isStale).toBe(false);
    expect(AsyncStorage.setItem).toHaveBeenCalledWith(
      '@contract_registry',
      expect.stringContaining('C123')
    );
  });

  it('persists the response ETag alongside the cached data on a 200', async () => {
    const mockBody = envelope({ quickex: { id: 'C123', version: 1 } });
    global.fetch = jest.fn(() =>
      Promise.resolve({
        ok: true,
        status: 200,
        headers: responseHeaders({ ETag: 'W/"reg-1"' }),
        json: () => Promise.resolve(mockBody),
      })
    ) as jest.Mock;
    (AsyncStorage.getItem as jest.Mock).mockResolvedValue(null);

    await ContractRegistryService.sync('http://localhost');

    const calls = (AsyncStorage.setItem as jest.Mock).mock.calls;
    const stored = JSON.parse(calls[calls.length - 1][1]);
    expect(stored.etag).toBe('W/"reg-1"');
    expect(stored.data.quickex.id).toBe('C123');
    // First sync has no cached ETag, so no conditional header is sent.
    expect((global.fetch as jest.Mock).mock.calls[0][1].headers['If-None-Match']).toBeUndefined();
  });

  it('sends the cached ETag as If-None-Match and reuses the cache on 304', async () => {
    const timestamp = Date.now();
    (AsyncStorage.getItem as jest.Mock).mockResolvedValue(JSON.stringify({
      timestamp,
      data: { quickex: { id: 'C456', version: 1 } },
      etag: 'W/"reg-1"',
    }));
    const json = jest.fn();
    global.fetch = jest.fn(() =>
      Promise.resolve({ ok: false, status: 304, headers: responseHeaders(), json })
    ) as jest.Mock;

    const result = await ContractRegistryService.sync('http://localhost');

    expect(global.fetch).toHaveBeenCalledWith('http://localhost/contracts/registry', {
      headers: { 'If-None-Match': 'W/"reg-1"' },
    });
    expect(json).not.toHaveBeenCalled();
    expect(result.registry.quickex.id).toBe('C456');
    expect(result.fetchedAt).toBe(timestamp);
    expect(result.source).toBe('cache');
    expect(result.isStale).toBe(false);
  });

  it('replaces the cached ETag and data when a conditional sync returns changed data', async () => {
    (AsyncStorage.getItem as jest.Mock).mockResolvedValue(JSON.stringify({
      timestamp: Date.now(),
      data: { quickex: { id: 'C456', version: 1 } },
      etag: 'W/"reg-1"',
    }));
    const freshBody = envelope({ quickex: { id: 'C999', version: 2 } }, { version: 2, etag: 'W/"reg-2"' });
    global.fetch = jest.fn(() =>
      Promise.resolve({
        ok: true,
        status: 200,
        headers: responseHeaders({ ETag: 'W/"reg-2"' }),
        json: () => Promise.resolve(freshBody),
      })
    ) as jest.Mock;

    const result = await ContractRegistryService.sync('http://localhost');

    expect((global.fetch as jest.Mock).mock.calls[0][1].headers['If-None-Match']).toBe('W/"reg-1"');
    expect(result.registry.quickex.id).toBe('C999');
    expect(result.registry.quickex.version).toBe(2);
    expect(result.source).toBe('network');

    const calls = (AsyncStorage.setItem as jest.Mock).mock.calls;
    const stored = JSON.parse(calls[calls.length - 1][1]);
    expect(stored.etag).toBe('W/"reg-2"');
    expect(stored.data.quickex.id).toBe('C999');
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

