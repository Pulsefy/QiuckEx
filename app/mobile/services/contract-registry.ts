import AsyncStorage from '@react-native-async-storage/async-storage';
import type { ContractEntry } from '../types/runtime-config';

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
  etag?: string;
}

let memoryRegistry: ContractRegistry | null = null;

function isContractRegistryEnvelope(value: unknown): value is ContractRegistryEnvelope {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as ContractRegistryEnvelope).data === 'object' &&
    (value as ContractRegistryEnvelope).data !== null
  );
}

async function getCachedRegistry(): Promise<ContractRegistryCache | null> {
  try {
    const cached = await AsyncStorage.getItem(CACHE_KEY);
    if (!cached) return null;
    return JSON.parse(cached) as ContractRegistryCache;
  } catch {
    return null;
  }
}

export const ContractRegistryService = {
  async sync(backendUrl: string): Promise<ContractRegistrySyncResult> {
    // Retrieve the cached envelope so its ETag can drive a conditional request.
    const cachedEnvelope = await getCachedRegistry();

    const headers: Record<string, string> = {};
    if (cachedEnvelope?.etag) {
      headers['If-None-Match'] = cachedEnvelope.etag;
    }

    try {
      const response = await fetch(`${backendUrl}/contracts/registry`, { headers });

      // 304 Not Modified — the cached registry is still authoritative.
      if (response.status === 304 && cachedEnvelope) {
        memoryRegistry = cachedEnvelope.data;
        return {
          registry: cachedEnvelope.data,
          fetchedAt: cachedEnvelope.timestamp,
          isStale: false,
          source: 'cache',
        };
      }

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
      const etag = response.headers?.get?.('ETag') || body.etag;
      const timestamp = Date.now();
      memoryRegistry = data;
      await AsyncStorage.setItem(CACHE_KEY, JSON.stringify({
        timestamp,
        data,
        etag
      }));
      return {
        registry: data,
        fetchedAt: timestamp,
        isStale: false,
        source: 'network',
      };
    } catch (error) {
      if (cachedEnvelope) {
        memoryRegistry = cachedEnvelope.data;
        // Serve stale cache if offline or backend returned bad data
        return {
          registry: cachedEnvelope.data,
          fetchedAt: cachedEnvelope.timestamp,
          isStale: Date.now() - cachedEnvelope.timestamp > REGISTRY_CACHE_TTL_MS,
          source: 'cache',
        };
      }
      const reason = error instanceof Error ? error.message : 'unknown error';
      throw new Error(`Registry unavailable and no cache found: ${reason}`);
    }
  },

  async populateFromBootstrap(
    contracts: ContractEntry[],
    networkPassphrase?: string,
  ): Promise<ContractRegistry> {
    const registry: ContractRegistry = {};
    for (const c of contracts) {
      registry[c.contractId] = {
        id: c.address,
        wasmHash: '',
        version: c.version ? parseInt(c.version, 10) || 1 : 1,
        schemaVersion: c.version ?? '1.0.0',
        schemaCompatibility: { min: '1.0.0', max: '2.0.0' },
        networkPassphrase: networkPassphrase ?? '',
        updatedAt: c.deployedAt ?? new Date().toISOString(),
        metadata: { address: c.address, version: c.version },
      };
    }
    memoryRegistry = registry;
    await AsyncStorage.setItem(
      CACHE_KEY,
      JSON.stringify({
        timestamp: Date.now(),
        data: registry,
      }),
    );
    return registry;
  },

  async getContract(name: string): Promise<string> {
    if (memoryRegistry && memoryRegistry[name]) {
      return memoryRegistry[name].id;
    }
    const cached = await AsyncStorage.getItem(CACHE_KEY);
    if (!cached) throw new Error('Registry missing');
    const registry = JSON.parse(cached).data;
    if (!registry[name]) throw new Error(`Contract ${name} missing from registry`);
    return registry[name].id;
  },

  async getContractEntry(name: string): Promise<ContractRegistryEntry | null> {
    if (memoryRegistry && memoryRegistry[name]) {
      return memoryRegistry[name];
    }
    const cached = await AsyncStorage.getItem(CACHE_KEY);
    if (!cached) return null;
    try {
      const registry = JSON.parse(cached).data;
      return registry[name] ?? null;
    } catch {
      return null;
    }
  },

  async getAllContracts(): Promise<ContractRegistry> {
    if (memoryRegistry) {
      return memoryRegistry;
    }
    const cached = await AsyncStorage.getItem(CACHE_KEY);
    if (!cached) return {};
    try {
      const registry = JSON.parse(cached).data;
      return registry ?? {};
    } catch {
      return {};
    }
  },

  clearMemoryCache(): void {
    memoryRegistry = null;
  },
};

