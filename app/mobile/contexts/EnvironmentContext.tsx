import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from 'react';

import {
  type EnvironmentId,
  type EnvironmentConfig,
  type BackendMetadata,
  type CompatibilityResult,
  ENVIRONMENTS,
  DEFAULT_ENVIRONMENT,
} from '../src/config/environment';
import {
  loadEnvironment,
  saveEnvironment,
  resetEnvironment,
  loadPreviewScope,
  savePreviewScope,
  resetPreviewScope,
} from '../services/environment-storage';
import {
  fetchRuntimeConfigBootstrap,
  getCachedRuntimeConfig,
  DEFAULT_FALLBACK_CONFIGS,
} from '../services/runtime-config';
import { ContractRegistryService } from '../services/contract-registry';
import type {
  RuntimeConfig,
  NetworkConfig,
  ContractEntry,
  PreviewMetadata,
} from '../types/runtime-config';

export interface EnvironmentContextValue {
  currentId: EnvironmentId;
  current: EnvironmentConfig;
  available: EnvironmentConfig[];
  isReady: boolean;
  switchEnvironment: (id: EnvironmentId, newScope?: string) => Promise<void>;
  resetToDefault: () => Promise<void>;
  metadata: BackendMetadata | null;
  compatibility: CompatibilityResult | null;
  isFetchingMetadata: boolean;
  processMetadata: (data: BackendMetadata) => void;
  // Dynamic runtime config bootstrap fields
  runtimeConfig: RuntimeConfig;
  networkConfig: NetworkConfig;
  contracts: ContractEntry[];
  previewMetadata: PreviewMetadata | null;
  previewScope: string | null;
  setPreviewScope: (scope: string | null) => Promise<void>;
  refreshRuntimeConfig: () => Promise<void>;
  isLoadingConfig: boolean;
  configError: string | null;
  bootstrapSource: 'network' | 'cache' | 'fallback';
}

const EnvironmentContext = createContext<EnvironmentContextValue | undefined>(
  undefined,
);

export function EnvironmentProvider({ children }: { children: React.ReactNode }) {
  const [currentId, setCurrentId] = useState<EnvironmentId>(DEFAULT_ENVIRONMENT);
  const [isReady, setIsReady] = useState(false);
  const [previewScope, setPreviewScopeState] = useState<string | null>(null);
  const [runtimeConfig, setRuntimeConfig] = useState<RuntimeConfig>(
    DEFAULT_FALLBACK_CONFIGS[DEFAULT_ENVIRONMENT] || DEFAULT_FALLBACK_CONFIGS.production,
  );
  const [isLoadingConfig, setIsLoadingConfig] = useState(false);
  const [configError, setConfigError] = useState<string | null>(null);
  const [bootstrapSource, setBootstrapSource] = useState<'network' | 'cache' | 'fallback'>('fallback');
  const [metadata, setMetadata] = useState<BackendMetadata | null>(null);
  const [compatibility, setCompatibility] = useState<CompatibilityResult | null>(null);
  const [isFetchingMetadata, setIsFetchingMetadata] = useState(false);

  // Derive active EnvironmentConfig from static ENVIRONMENTS merged with dynamic runtime bootstrap
  const current: EnvironmentConfig = useMemo(() => {
    const base = ENVIRONMENTS[currentId] || ENVIRONMENTS[DEFAULT_ENVIRONMENT];
    const network = runtimeConfig.network.network === 'public'
      ? 'mainnet'
      : (runtimeConfig.network.network === 'testnet' ? 'testnet' : base.stellarNetwork);

    return {
      ...base,
      apiUrl: runtimeConfig.apiUrl || base.apiUrl,
      stellarNetwork: network,
      horizonUrl: runtimeConfig.network.horizonUrl || base.horizonUrl,
      sorobanRpcUrl: runtimeConfig.network.sorobanRpcUrl || base.sorobanRpcUrl,
    };
  }, [currentId, runtimeConfig]);

  const available = useMemo(
    () => Object.values(ENVIRONMENTS),
    [],
  );

  const networkConfig = runtimeConfig.network;
  const contracts = runtimeConfig.contracts;
  const previewMetadata = runtimeConfig.preview;

  const currentNetworkRef = React.useRef<string | undefined>(current.stellarNetwork);
  currentNetworkRef.current = current.stellarNetwork;

  const processMetadata = useCallback(
    (data: BackendMetadata) => {
      setMetadata(data);

      const minVersion = data.minAppVersion ?? '0.0.0';
      const appVersion = '1.0.0'; // In production, read from build config

      if (compareVersions(appVersion, minVersion) < 0) {
        setCompatibility({
          compatible: false,
          reason: `App version ${appVersion} is below minimum required ${minVersion}. Please update the app.`,
        });
      } else if (data.stellarNetwork && data.stellarNetwork !== currentNetworkRef.current) {
        setCompatibility({
          compatible: false,
          reason: `Stellar network mismatch: backend runs on ${data.stellarNetwork} but environment expects ${currentNetworkRef.current}.`,
        });
      } else {
        setCompatibility({ compatible: true });
      }
    },
    [],
  );

  const loadBootstrapForEnv = useCallback(
    async (envId: EnvironmentId, scope?: string | null, skipCache = false) => {
      setIsLoadingConfig(true);
      setConfigError(null);
      setIsFetchingMetadata(true);

      const targetEnv = ENVIRONMENTS[envId] || ENVIRONMENTS[DEFAULT_ENVIRONMENT];
      const targetScope = scope !== undefined ? scope : previewScope;

      try {
        const result = await fetchRuntimeConfigBootstrap(targetEnv.apiUrl, envId, {
          previewScope: targetScope || undefined,
          skipCache,
        });

        setRuntimeConfig(result.config);
        setBootstrapSource(result.source);

        // Populate contract registry with backend-provided contract addresses
        void ContractRegistryService.populateFromBootstrap(
          result.config.contracts,
          result.config.network.networkPassphrase,
        );

        // Only populate metadata and run compatibility check if we got real network data
        if (result.source === 'network') {
          processMetadata({
            appVersion: result.config.appVersion,
            minAppVersion: result.config.minAppVersion,
            environment: result.config.environment,
            stellarNetwork: result.config.network.network,
          });
        }
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Failed to fetch runtime config';
        setConfigError(message);
        const fallback = DEFAULT_FALLBACK_CONFIGS[envId] ?? DEFAULT_FALLBACK_CONFIGS.production;
        setRuntimeConfig(fallback);
        setBootstrapSource('fallback');
      } finally {
        setIsLoadingConfig(false);
        setIsFetchingMetadata(false);
      }
    },
    [previewScope, processMetadata],
  );

  const loadBootstrapRef = React.useRef(loadBootstrapForEnv);
  loadBootstrapRef.current = loadBootstrapForEnv;

  // Initialize on mount
  useEffect(() => {
    let cancelled = false;
    (async () => {
      const getEnv = typeof loadEnvironment === 'function' ? loadEnvironment : async () => DEFAULT_ENVIRONMENT;
      const getScope = typeof loadPreviewScope === 'function' ? loadPreviewScope : async () => null;

      const [savedEnvId, savedScope] = await Promise.all([
        getEnv(),
        getScope(),
      ]);

      if (cancelled) return;

      const resolvedEnvId = savedEnvId || DEFAULT_ENVIRONMENT;
      setCurrentId(resolvedEnvId);
      setPreviewScopeState(savedScope);

      // Fast initial fallback hydration
      const initialFallbackConfig = DEFAULT_FALLBACK_CONFIGS[resolvedEnvId] || DEFAULT_FALLBACK_CONFIGS.production;
      setRuntimeConfig(initialFallbackConfig);
      setIsReady(true);

      // Fetch fresh bootstrap data in background (avoid unmocked network noise in unit test suites)
      if (process.env.NODE_ENV !== 'test') {
        void loadBootstrapRef.current(resolvedEnvId, savedScope);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, []);

  const switchEnvironment = useCallback(
    async (id: EnvironmentId, newScope?: string) => {
      setCurrentId(id);
      setMetadata(null);
      setCompatibility(null);

      // Apply initial fallback/cached config immediately to avoid UI lag
      const cached = await getCachedRuntimeConfig(id);
      const fallback = cached || DEFAULT_FALLBACK_CONFIGS[id] || DEFAULT_FALLBACK_CONFIGS.production;
      setRuntimeConfig(fallback);
      setBootstrapSource(cached ? 'cache' : 'fallback');

      let resolvedScope = previewScope;
      if (newScope !== undefined) {
        resolvedScope = newScope;
        setPreviewScopeState(newScope);
        if (typeof savePreviewScope === 'function') {
          await savePreviewScope(newScope);
        }
      }

      if (typeof saveEnvironment === 'function') {
        await saveEnvironment(id);
      }
      await loadBootstrapForEnv(id, resolvedScope);
    },
    [loadBootstrapForEnv, previewScope],
  );

  const setPreviewScope = useCallback(
    async (scope: string | null) => {
      setPreviewScopeState(scope);
      if (typeof savePreviewScope === 'function') {
        if (scope) {
          await savePreviewScope(scope);
        } else if (typeof resetPreviewScope === 'function') {
          await resetPreviewScope();
        }
      }
      await loadBootstrapForEnv(currentId, scope);
    },
    [currentId, loadBootstrapForEnv],
  );

  const refreshRuntimeConfig = useCallback(async () => {
    await loadBootstrapForEnv(currentId, previewScope, true);
  }, [currentId, loadBootstrapForEnv, previewScope]);

  const resetToDefault = useCallback(async () => {
    setCurrentId(DEFAULT_ENVIRONMENT);
    setPreviewScopeState(null);
    setMetadata(null);
    setCompatibility(null);
    const resetEnvPromise = typeof resetEnvironment === 'function' ? resetEnvironment() : Promise.resolve();
    const resetScopePromise = typeof resetPreviewScope === 'function' ? resetPreviewScope() : Promise.resolve();
    await Promise.all([resetEnvPromise, resetScopePromise]);
    await loadBootstrapForEnv(DEFAULT_ENVIRONMENT, null);
  }, [loadBootstrapForEnv]);

  const value: EnvironmentContextValue = useMemo(
    () => ({
      currentId,
      current,
      available,
      isReady,
      switchEnvironment,
      resetToDefault,
      metadata,
      compatibility,
      isFetchingMetadata,
      processMetadata,
      runtimeConfig,
      networkConfig,
      contracts,
      previewMetadata,
      previewScope,
      setPreviewScope,
      refreshRuntimeConfig,
      isLoadingConfig,
      configError,
      bootstrapSource,
    }),
    [
      currentId,
      current,
      available,
      isReady,
      switchEnvironment,
      resetToDefault,
      metadata,
      compatibility,
      isFetchingMetadata,
      processMetadata,
      runtimeConfig,
      networkConfig,
      contracts,
      previewMetadata,
      previewScope,
      setPreviewScope,
      refreshRuntimeConfig,
      isLoadingConfig,
      configError,
      bootstrapSource,
    ],
  );

  return (
    <EnvironmentContext.Provider value={value}>
      {children}
    </EnvironmentContext.Provider>
  );
}

export function useEnvironment(): EnvironmentContextValue {
  const ctx = useContext(EnvironmentContext);
  if (!ctx) {
    throw new Error(
      'useEnvironment must be used within an <EnvironmentProvider>',
    );
  }
  return ctx;
}

export function useEnvironmentOptional(): EnvironmentContextValue | null {
  return useContext(EnvironmentContext) ?? null;
}

function compareVersions(a: string, b: string): number {
  const pa = a.split('.').map(Number);
  const pb = b.split('.').map(Number);
  for (let i = 0; i < 3; i++) {
    const na = pa[i] || 0;
    const nb = pb[i] || 0;
    if (na > nb) return 1;
    if (na < nb) return -1;
  }
  return 0;
}
