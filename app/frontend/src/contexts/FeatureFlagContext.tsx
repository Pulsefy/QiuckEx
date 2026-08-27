"use client";

import { createContext, useContext, useEffect, useState } from 'react';
import {
  DEFAULT_FEATURE_FLAGS,
  FeatureFlagKey,
  FeatureFlagValues,
} from '@/config/feature-flags.config';
import { fetchFeatureFlags } from '@/services/feature-flags.service';

type FeatureFlagContextValue = {
  flags: FeatureFlagValues;
  isLoading: boolean;
  error: Error | null;
  isEnabled: (key: FeatureFlagKey) => boolean;
  refresh: () => Promise<void>;
};

const FeatureFlagContext = createContext<FeatureFlagContextValue | null>(null);

/**
 * Loads flags after mount without blocking children. Values remain cached in
 * sessionStorage for this browser tab; refresh() is the explicit refresh path.
 */
export function FeatureFlagProvider({ children }: { children: React.ReactNode }) {
  const [flags, setFlags] = useState<FeatureFlagValues>(DEFAULT_FEATURE_FLAGS);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);

  const refresh = async () => {
    setIsLoading(true);
    setError(null);
    try {
      setFlags(await fetchFeatureFlags(true));
    } catch (refreshError) {
      setError(refreshError instanceof Error ? refreshError : new Error('Feature flag refresh failed'));
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    let mounted = true;

    void fetchFeatureFlags().then((loadedFlags) => {
      if (mounted) {
        setFlags(loadedFlags);
        setIsLoading(false);
      }
    });

    return () => {
      mounted = false;
    };
  }, []);

  return (
    <FeatureFlagContext.Provider
      value={{
        flags,
        isLoading,
        error,
        isEnabled: (key) => flags[key] ?? false,
        refresh,
      }}
    >
      {children}
    </FeatureFlagContext.Provider>
  );
}

export function useFeatureFlags(): FeatureFlagContextValue {
  const context = useContext(FeatureFlagContext);
  if (!context) throw new Error('useFeatureFlags must be used inside FeatureFlagProvider');
  return context;
}

export function useFeatureFlag(key: FeatureFlagKey): boolean {
  return useFeatureFlags().isEnabled(key);
}