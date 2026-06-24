import { ContractRegistryService, REGISTRY_CACHE_TTL_MS } from '../services/contract-registry';
import AsyncStorage from '@react-native-async-storage/async-storage';

describe('ContractRegistryService', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    jest.restoreAllMocks();
  });

  it('fetches fresh registry and caches it', async () => {
    const mockData = { Escrow: { id: 'C123', version: '1.0' } };
    global.fetch = jest.fn(() => 
      Promise.resolve({ ok: true, json: () => Promise.resolve(mockData) })
    ) as jest.Mock;

    const result = await ContractRegistryService.sync('http://localhost');
    expect(result.registry.Escrow.id).toBe('C123');
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
      data: { Escrow: { id: 'C456', version: '1.0' } }
    });
    (AsyncStorage.getItem as jest.Mock).mockResolvedValue(cachedState);

    const result = await ContractRegistryService.sync('http://localhost');
    expect(result.registry.Escrow.id).toBe('C456');
    expect(result.source).toBe('cache');
    expect(result.isStale).toBe(false);
  });

  it('marks cached registry data stale after the cache ttl', async () => {
    const now = 1_800_000_000_000;
    jest.spyOn(Date, 'now').mockReturnValue(now);
    global.fetch = jest.fn(() => Promise.reject(new Error('Network drop')));

    const cachedState = JSON.stringify({
      timestamp: now - REGISTRY_CACHE_TTL_MS - 1,
      data: { Escrow: { id: 'C789', version: '1.0' } }
    });
    (AsyncStorage.getItem as jest.Mock).mockResolvedValue(cachedState);

    const result = await ContractRegistryService.sync('http://localhost');
    expect(result.registry.Escrow.id).toBe('C789');
    expect(result.source).toBe('cache');
    expect(result.isStale).toBe(true);
  });

  it('refreshes stale registry data when the network recovers', async () => {
    const now = 1_800_000_000_000;
    jest.spyOn(Date, 'now').mockReturnValue(now);
    const freshData = { Escrow: { id: 'C999', version: '2.0' } };
    global.fetch = jest.fn()
      .mockRejectedValueOnce(new Error('Network drop'))
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(freshData) });

    const cachedState = JSON.stringify({
      timestamp: now - REGISTRY_CACHE_TTL_MS - 1,
      data: { Escrow: { id: 'C789', version: '1.0' } }
    });
    (AsyncStorage.getItem as jest.Mock).mockResolvedValue(cachedState);

    const staleResult = await ContractRegistryService.sync('http://localhost');
    const refreshedResult = await ContractRegistryService.sync('http://localhost');

    expect(staleResult.isStale).toBe(true);
    expect(refreshedResult.registry.Escrow.id).toBe('C999');
    expect(refreshedResult.registry.Escrow.version).toBe('2.0');
    expect(refreshedResult.source).toBe('network');
    expect(refreshedResult.isStale).toBe(false);
  });

  it('throws error if network fails and cache is empty', async () => {
    global.fetch = jest.fn(() => Promise.reject(new Error('Network drop')));
    (AsyncStorage.getItem as jest.Mock).mockResolvedValue(null);

    await expect(ContractRegistryService.sync('http://localhost'))
      .rejects.toThrow('Registry unavailable and no cache found');
  });
});
