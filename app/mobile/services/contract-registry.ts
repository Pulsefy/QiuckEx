import AsyncStorage from '@react-native-async-storage/async-storage';

const CACHE_KEY = '@contract_registry';
export const REGISTRY_CACHE_TTL_MS = 1000 * 60 * 60 * 24; // 24 hours

export interface ContractRegistry {
  [key: string]: { id: string; version: string };
}

export interface ContractRegistrySyncResult {
  registry: ContractRegistry;
  fetchedAt: number;
  isStale: boolean;
  source: 'network' | 'cache';
}

interface ContractRegistryCache {
  timestamp: number;
  data: ContractRegistry;
}

export const ContractRegistryService = {
  async sync(backendUrl: string): Promise<ContractRegistrySyncResult> {
    try {
      const response = await fetch(`${backendUrl}/api/contracts/registry`);
      if (!response.ok) throw new Error('Failed to fetch registry');
      
      const data = await response.json() as ContractRegistry;
      const timestamp = Date.now();
      await AsyncStorage.setItem(CACHE_KEY, JSON.stringify({
        timestamp,
        data
      }));
      return {
        registry: data,
        fetchedAt: timestamp,
        isStale: false,
        source: 'network',
      };
    } catch (error) {
      const cached = await AsyncStorage.getItem(CACHE_KEY);
      if (cached) {
        const parsed = JSON.parse(cached) as ContractRegistryCache;
        // Serve stale cache if offline
        return {
          registry: parsed.data,
          fetchedAt: parsed.timestamp,
          isStale: Date.now() - parsed.timestamp > REGISTRY_CACHE_TTL_MS,
          source: 'cache',
        };
      }
      throw new Error('Registry unavailable and no cache found');
    }
  },

  async getContract(name: string): Promise<string> {
    const cached = await AsyncStorage.getItem(CACHE_KEY);
    if (!cached) throw new Error('Registry missing');
    const registry = JSON.parse(cached).data;
    if (!registry[name]) throw new Error(`Contract ${name} missing from registry`);
    return registry[name].id;
  }
};
