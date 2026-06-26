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
} from '../services/environment-storage';

export interface EnvironmentContextValue {
  currentId: EnvironmentId;
  current: EnvironmentConfig;
  available: EnvironmentConfig[];
  isReady: boolean;
  switchEnvironment: (id: EnvironmentId) => Promise<void>;
  resetToDefault: () => Promise<void>;
  metadata: BackendMetadata | null;
  compatibility: CompatibilityResult | null;
  isFetchingMetadata: boolean;
  fetchMetadata: () => Promise<void>;
}

const EnvironmentContext = createContext<EnvironmentContextValue | undefined>(
  undefined,
);

export function EnvironmentProvider({ children }: { children: React.ReactNode }) {
  const [currentId, setCurrentId] = useState<EnvironmentId>(DEFAULT_ENVIRONMENT);
  const [isReady, setIsReady] = useState(false);
  const [metadata, setMetadata] = useState<BackendMetadata | null>(null);
  const [compatibility, setCompatibility] = useState<CompatibilityResult | null>(null);
  const [isFetchingMetadata, setIsFetchingMetadata] = useState(false);

  const current = ENVIRONMENTS[currentId];

  const available = useMemo(
    () => Object.values(ENVIRONMENTS),
    [],
  );

  useEffect(() => {
    let cancelled = false;
    (async () => {
      const id = await loadEnvironment();
      if (cancelled) return;
      setCurrentId(id);
      setIsReady(true);
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const fetchMetadata = useCallback(async () => {
    setIsFetchingMetadata(true);
    setCompatibility(null);
    try {
      const response = await fetch(`${current.apiUrl}/health`, {
        method: 'GET',
        headers: { 'Content-Type': 'application/json' },
      });
      if (!response.ok) {
        setCompatibility({
          compatible: false,
          reason: `Backend returned status ${response.status}`,
        });
        return;
      }
      const data = (await response.json()) as BackendMetadata;
      setMetadata(data);

      const minVersion = data.minAppVersion ?? '0.0.0';
      const appVersion = '1.0.0'; // In production, read from build config

      if (compareVersions(appVersion, minVersion) < 0) {
        setCompatibility({
          compatible: false,
          reason: `App version ${appVersion} is below minimum required ${minVersion}. Please update the app.`,
        });
      } else if (data.stellarNetwork && data.stellarNetwork !== current.stellarNetwork) {
        setCompatibility({
          compatible: false,
          reason: `Stellar network mismatch: backend runs on ${data.stellarNetwork} but environment expects ${current.stellarNetwork}.`,
        });
      } else {
        setCompatibility({ compatible: true });
      }
    } catch (error) {
      setCompatibility({
        compatible: false,
        reason: error instanceof Error ? error.message : 'Failed to reach backend',
      });
    } finally {
      setIsFetchingMetadata(false);
    }
  }, [current.apiUrl, current.stellarNetwork]);

  const switchEnvironment = useCallback(
    async (id: EnvironmentId) => {
      setCurrentId(id);
      setMetadata(null);
      setCompatibility(null);
      await saveEnvironment(id);
    },
    [],
  );

  const resetToDefault = useCallback(async () => {
    setCurrentId(DEFAULT_ENVIRONMENT);
    setMetadata(null);
    setCompatibility(null);
    await resetEnvironment();
  }, []);

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
      fetchMetadata,
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
      fetchMetadata,
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
