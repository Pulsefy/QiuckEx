import { ContractRegistryService } from '../services/contract-registry';
import AsyncStorage from '@react-native-async-storage/async-storage';

describe('ContractRegistryService', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('fetches fresh registry and caches it', async () => {
    const mockData = { Escrow: { id: 'C123', version: '1.0' } };
    global.fetch = jest.fn(() => 
      Promise.resolve({ ok: true, json: () => Promise.resolve(mockData) })
    ) as jest.Mock;

    const data = await ContractRegistryService.sync('http://localhost');
    expect(data.Escrow.id).toBe('C123');
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

    const data = await ContractRegistryService.sync('http://localhost');
    expect(data.Escrow.id).toBe('C456');
  });

  it('throws error if network fails and cache is empty', async () => {
    global.fetch = jest.fn(() => Promise.reject(new Error('Network drop')));
    (AsyncStorage.getItem as jest.Mock).mockResolvedValue(null);

    await expect(ContractRegistryService.sync('http://localhost'))
      .rejects.toThrow('Registry unavailable and no cache found');
  });
});