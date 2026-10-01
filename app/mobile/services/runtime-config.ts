import AsyncStorage from '@react-native-async-storage/async-storage';
import { type EnvironmentId, ENVIRONMENTS } from '../src/config/environment';
import type {
  RuntimeConfig,
  PartialRuntimeConfigResponse,
  ContractEntry,
} from '../types/runtime-config';

const CONFIG_CACHE_PREFIX = '@quickex/runtime_config_';
export const CONFIG_CACHE_TTL_MS = 1000 * 60 * 60 * 24; // 24 hours

export interface BootstrapResult {
  config: RuntimeConfig;
  source: 'network' | 'cache' | 'fallback';
}

interface CachedConfigEnvelope {
  config: RuntimeConfig;
  etag?: string;
  cachedAt: number;
}

export const DEFAULT_FALLBACK_CONFIGS: Record<EnvironmentId, RuntimeConfig> = {
  production: {
    environment: 'production',
    apiUrl: 'https://api.quickex.org',
    appVersion: '1.0.0',
    minAppVersion: '1.0.0',
    network: {
      network: 'public',
      horizonUrl: 'https://horizon.stellar.org',
      sorobanRpcUrl: 'https://soroban.stellar.org',
      networkPassphrase: 'Public Global Stellar Network ; July 2015',
    },
    contracts: [
      {
        contractId: 'token-bridge',
        address: 'CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC',
        version: '1.0.0',
      },
      {
        contractId: 'native-asset',
        address: 'CAS3J7GYLGXMF6TDJBBYYSE3HQ6BBSMLNUQ34T6TZMYMW2EZH3WOIECX',
        version: '1.0.0',
      },
      {
        contractId: 'dex-router',
        address: 'CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM',
        version: '1.0.0',
      },
    ],
    featureFlags: {
      enableAnalytics: true,
      enableCrashReporting: true,
      enableBiometrics: true,
      enableOfflineQueue: true,
    },
    preview: null,
    mobileVersionPolicy: {
      minAppVersion: '1.0.0',
      latestAppVersion: '1.0.0',
      forceUpdate: false,
    },
  },
  staging: {
    environment: 'staging',
    apiUrl: 'https://staging-api.quickex.org',
    appVersion: '1.0.0',
    minAppVersion: '1.0.0',
    network: {
      network: 'testnet',
      horizonUrl: 'https://horizon-testnet.stellar.org',
      sorobanRpcUrl: 'https://soroban-testnet.stellar.org',
      networkPassphrase: 'Test SDF Network ; September 2015',
    },
    contracts: [
      {
        contractId: 'token-bridge',
        address: 'CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM',
        version: '1.0.0',
      },
      {
        contractId: 'native-asset',
        address: 'CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC',
        version: '1.0.0',
      },
      {
        contractId: 'dex-router',
        address: 'CBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB3KM',
        version: '1.0.0',
      },
    ],
    featureFlags: {
      enableAnalytics: true,
      enableCrashReporting: true,
      enableBiometrics: true,
      enableOfflineQueue: true,
      enableDebugMenu: true,
    },
    preview: null,
    mobileVersionPolicy: {
      minAppVersion: '1.0.0',
      latestAppVersion: '1.0.0',
      forceUpdate: false,
    },
  },
  testnet: {
    environment: 'testnet',
    apiUrl: 'https://testnet-api.quickex.org',
    appVersion: '1.0.0',
    minAppVersion: '1.0.0',
    network: {
      network: 'testnet',
      horizonUrl: 'https://horizon-testnet.stellar.org',
      sorobanRpcUrl: 'https://soroban-testnet.stellar.org',
      networkPassphrase: 'Test SDF Network ; September 2015',
    },
    contracts: [
      {
        contractId: 'token-bridge',
        address: 'CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM',
        version: '1.0.0',
      },
      {
        contractId: 'native-asset',
        address: 'CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC',
        version: '1.0.0',
      },
      {
        contractId: 'dex-router',
        address: 'CBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB3KM',
        version: '1.0.0',
      },
    ],
    featureFlags: {
      enableAnalytics: false,
      enableCrashReporting: true,
      enableBiometrics: true,
      enableOfflineQueue: true,
      enableDebugMenu: true,
    },
    preview: null,
    mobileVersionPolicy: {
      minAppVersion: '1.0.0',
      latestAppVersion: '1.0.0',
      forceUpdate: false,
    },
  },
  'branch-preview': {
    environment: 'branch-preview',
    apiUrl: 'https://preview-api.quickex.org',
    appVersion: '1.0.0',
    minAppVersion: '1.0.0',
    network: {
      network: 'testnet',
      horizonUrl: 'https://horizon-testnet.stellar.org',
      sorobanRpcUrl: 'https://soroban-testnet.stellar.org',
      networkPassphrase: 'Test SDF Network ; September 2015',
    },
    contracts: [
      {
        contractId: 'token-bridge',
        address: 'CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM',
        version: '1.0.0',
      },
      {
        contractId: 'native-asset',
        address: 'CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC',
        version: '1.0.0',
      },
      {
        contractId: 'dex-router',
        address: 'CBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB3KM',
        version: '1.0.0',
      },
    ],
    featureFlags: {
      enableAnalytics: false,
      enableCrashReporting: false,
      enableBiometrics: true,
      enableOfflineQueue: true,
      enableDebugMenu: true,
    },
    preview: {
      scope: 'default',
      branch: 'preview',
    },
    mobileVersionPolicy: {
      minAppVersion: '1.0.0',
      latestAppVersion: '1.0.0',
      forceUpdate: false,
    },
  },
};

/**
 * Merges partial/incomplete backend runtime config with solid fallbacks.
 * Ensures the app never crashes or misconfigures due to missing payload fields.
 */
export function sanitizeRuntimeConfig(
  data: PartialRuntimeConfigResponse | null | undefined,
  envId: EnvironmentId,
  fallbackScope?: string | null,
): RuntimeConfig {
  const fallback = DEFAULT_FALLBACK_CONFIGS[envId] ?? DEFAULT_FALLBACK_CONFIGS.production;

  if (!data || typeof data !== 'object') {
    return fallback;
  }

  // Network sanitization
  const network = {
    network: data.network?.network || fallback.network.network,
    horizonUrl: data.network?.horizonUrl || fallback.network.horizonUrl,
    sorobanRpcUrl: data.network?.sorobanRpcUrl || fallback.network.sorobanRpcUrl,
    networkPassphrase: data.network?.networkPassphrase || fallback.network.networkPassphrase,
  };

  // Contracts sanitization: merge backend contracts with fallback contracts
  const contractMap = new Map<string, ContractEntry>();
  for (const c of fallback.contracts) {
    contractMap.set(c.contractId, c);
  }
  if (Array.isArray(data.contracts)) {
    for (const c of data.contracts) {
      if (c && typeof c.contractId === 'string' && typeof c.address === 'string') {
        contractMap.set(c.contractId, {
          contractId: c.contractId,
          address: c.address,
          deployedAt: c.deployedAt,
          version: c.version || '1.0.0',
        });
      }
    }
  }
  const contracts = Array.from(contractMap.values());

  // Preview metadata sanitization
  let preview = fallback.preview;
  if (data.preview && typeof data.preview === 'object') {
    preview = {
      scope: data.preview.scope || fallbackScope || 'preview',
      branch: data.preview.branch || fallbackScope || 'preview',
      commitSha: data.preview.commitSha,
      deployedAt: data.preview.deployedAt,
      expiresAt: data.preview.expiresAt,
    };
  } else if (envId === 'branch-preview' && fallbackScope) {
    preview = {
      scope: fallbackScope,
      branch: fallbackScope,
    };
  }

  // Feature flags sanitization
  const featureFlags = {
    ...fallback.featureFlags,
    ...(data.featureFlags && typeof data.featureFlags === 'object' ? data.featureFlags : {}),
  };

  // Mobile version policy sanitization
  const mobileVersionPolicy = {
    minAppVersion: data.mobileVersionPolicy?.minAppVersion || data.minAppVersion || fallback.mobileVersionPolicy.minAppVersion,
    latestAppVersion: data.mobileVersionPolicy?.latestAppVersion || data.appVersion || fallback.mobileVersionPolicy.latestAppVersion,
    forceUpdate: Boolean(data.mobileVersionPolicy?.forceUpdate),
    updateUrl: data.mobileVersionPolicy?.updateUrl,
    message: data.mobileVersionPolicy?.message,
  };

  return {
    environment: (data.environment as EnvironmentId) || envId,
    apiUrl: data.apiUrl || fallback.apiUrl,
    appVersion: data.appVersion || fallback.appVersion,
    minAppVersion: data.minAppVersion || fallback.minAppVersion,
    network,
    contracts,
    featureFlags,
    preview,
    mobileVersionPolicy,
    etag: data.etag,
    fetchedAt: Date.now(),
  };
}

export async function getCachedRuntimeConfig(
  envId: EnvironmentId,
): Promise<RuntimeConfig | null> {
  try {
    const raw = await AsyncStorage.getItem(`${CONFIG_CACHE_PREFIX}${envId}`);
    if (!raw) return null;

    const envelope: CachedConfigEnvelope = JSON.parse(raw);
    const isExpired = Date.now() - envelope.cachedAt > CONFIG_CACHE_TTL_MS;
    if (isExpired) return null;

    return envelope.config;
  } catch {
    return null;
  }
}

export async function getCachedEnvelope(
  envId: EnvironmentId,
): Promise<CachedConfigEnvelope | null> {
  try {
    const raw = await AsyncStorage.getItem(`${CONFIG_CACHE_PREFIX}${envId}`);
    if (!raw) return null;
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

export async function setCachedRuntimeConfig(
  envId: EnvironmentId,
  config: RuntimeConfig,
  etag?: string,
): Promise<void> {
  try {
    const envelope: CachedConfigEnvelope = {
      config,
      etag,
      cachedAt: Date.now(),
    };
    await AsyncStorage.setItem(`${CONFIG_CACHE_PREFIX}${envId}`, JSON.stringify(envelope));
  } catch {
    // Non-fatal if cache write fails
  }
}

export async function clearRuntimeConfigCache(envId?: EnvironmentId): Promise<void> {
  try {
    if (envId) {
      await AsyncStorage.removeItem(`${CONFIG_CACHE_PREFIX}${envId}`);
    } else {
      const keys = Object.keys(DEFAULT_FALLBACK_CONFIGS).map((id) => `${CONFIG_CACHE_PREFIX}${id}`);
      for (const key of keys) {
        await AsyncStorage.removeItem(key);
      }
    }
  } catch {
    // Non-fatal
  }
}

export async function fetchRuntimeConfigBootstrap(
  baseUrl: string,
  envId: EnvironmentId,
  options?: {
    previewScope?: string;
    timeoutMs?: number;
    skipCache?: boolean;
  },
): Promise<BootstrapResult> {
  const fallback = DEFAULT_FALLBACK_CONFIGS[envId] ?? DEFAULT_FALLBACK_CONFIGS.production;
  const timeoutMs = options?.timeoutMs ?? 5000;

  // Retrieve cached envelope for conditional request (ETag)
  const cachedEnvelope = !options?.skipCache ? await getCachedEnvelope(envId) : null;

  // Build clean URL without duplicate slashes
  const cleanBase = baseUrl.replace(/\/+$/, '');
  const url = `${cleanBase}/v1/runtime-config`;

  const headers: Record<string, string> = {
    Accept: 'application/json',
  };

  if (options?.previewScope) {
    headers['X-Preview-Scope'] = options.previewScope;
  }

  if (cachedEnvelope?.etag && !options?.skipCache) {
    headers['If-None-Match'] = cachedEnvelope.etag;
  }

  const controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
  const timeoutId = controller ? setTimeout(() => controller.abort(), timeoutMs) : null;

  try {
    const response = await fetch(url, {
      method: 'GET',
      headers,
      signal: controller?.signal,
    });

    if (timeoutId) clearTimeout(timeoutId);

    // 304 Not Modified — cached config is valid
    if (response.status === 304 && cachedEnvelope?.config) {
      return {
        config: cachedEnvelope.config,
        source: 'cache',
      };
    }

    if (!response.ok) {
      throw new Error(`HTTP error ${response.status}`);
    }

    const payload: PartialRuntimeConfigResponse = await response.json();
    const etag = response.headers?.get?.('ETag') || payload.etag;
    const sanitized = sanitizeRuntimeConfig(payload, envId, options?.previewScope);
    sanitized.etag = etag;

    // Cache the fresh bootstrap config
    await setCachedRuntimeConfig(envId, sanitized, etag);

    return {
      config: sanitized,
      source: 'network',
    };
  } catch {
    if (timeoutId) clearTimeout(timeoutId);

    // If cached configuration is available, use it over hardcoded fallback
    if (cachedEnvelope?.config) {
      return {
        config: cachedEnvelope.config,
        source: 'cache',
      };
    }

    return {
      config: fallback,
      source: 'fallback',
    };
  }
}
