import AsyncStorage from '@react-native-async-storage/async-storage';

const CACHE_KEY = '@contract_registry';
export const REGISTRY_CACHE_TTL_MS = 1000 * 60 * 60 * 24; // 24 hours

export interface ContractRegistryEntry {
  id: string;
  wasmHash: string;
  version: number;
  schemaVersion: string;
  schemaCompatibility: { min: string; max: string };
  networkPassphrase: string;
  deploymentId?: string;
  initParams?: Record<string, unknown>;
  updatedAt: string;
  metadata?: Record<string, unknown>;
}

export interface ContractRegistry {
  [key: string]: ContractRegistryEntry;
}

interface ContractRegistryEnvelope {
  network: string;
  authoritative: boolean;
  version: number;
  etag: string;
  data: ContractRegistry;
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

function isContractRegistryEnvelope(value: unknown): value is ContractRegistryEnvelope {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as ContractRegistryEnvelope).data === 'object' &&
    (value as ContractRegistryEnvelope).data !== null
  );
}

export const ContractRegistryService = {
  async sync(backendUrl: string): Promise<ContractRegistrySyncResult> {
    try {
      const response = await fetch(`${backendUrl}/api/contracts/registry`);
      if (response.status === 404) {
        throw new Error('Contract registry route not found on backend');
      }
      if (!response.ok) {
        throw new Error(`Failed to fetch registry (status ${response.status})`);
      }

      const body: unknown = await response.json();
      if (!isContractRegistryEnvelope(body)) {
        throw new Error('Contract registry response payload is malformed');
      }

      const data = body.data;
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
        // Serve stale cache if offline or backend returned bad data
        return {
          registry: parsed.data,
          fetchedAt: parsed.timestamp,
          isStale: Date.now() - parsed.timestamp > REGISTRY_CACHE_TTL_MS,
          source: 'cache',
        };
      }
      const reason = error instanceof Error ? error.message : 'unknown error';
      throw new Error(`Registry unavailable and no cache found: ${reason}`);
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
