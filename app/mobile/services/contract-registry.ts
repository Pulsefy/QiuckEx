import AsyncStorage from '@react-native-async-storage/async-storage';

const CACHE_KEY = '@contract_registry';
const CACHE_TTL = 1000 * 60 * 60 * 24; // 24 hours

export interface ContractRegistry {
  [key: string]: { id: string; version: string };
}

export const ContractRegistryService = {
  async sync(backendUrl: string): Promise<ContractRegistry> {
    try {
      const response = await fetch(`${backendUrl}/api/contracts/registry`);
      if (!response.ok) throw new Error('Failed to fetch registry');
      
      const data = await response.json();
      await AsyncStorage.setItem(CACHE_KEY, JSON.stringify({
        timestamp: Date.now(),
        data
      }));
      return data;
    } catch (error) {
      const cached = await AsyncStorage.getItem(CACHE_KEY);
      if (cached) {
        const parsed = JSON.parse(cached);
        // Serve stale cache if offline
        return parsed.data;
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