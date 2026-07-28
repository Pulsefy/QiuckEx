import { useCallback, useEffect, useMemo, useState } from 'react';
import { ContractRegistryService } from '../services/contract-registry';

export type ContractRegistryStatus =
  | 'loading'
  | 'refreshing'
  | 'ready'
  | 'stale'
  | 'incompatible'
  | 'unavailable';

function formatLastUpdated(timestamp: number | null) {
  if (!timestamp) return 'Never updated';

  const elapsedMs = Date.now() - timestamp;
  const elapsedMinutes = Math.max(0, Math.floor(elapsedMs / 60000));

  if (elapsedMinutes < 1) return 'Updated just now';
  if (elapsedMinutes < 60) return `Updated ${elapsedMinutes}m ago`;

  const elapsedHours = Math.floor(elapsedMinutes / 60);
  if (elapsedHours < 24) return `Updated ${elapsedHours}h ago`;

  const elapsedDays = Math.floor(elapsedHours / 24);
  return `Updated ${elapsedDays}d ago`;
}

export function useContractRegistry(requiredContracts: string[], backendUrl: string) {
  const [isReady, setIsReady] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState<ContractRegistryStatus>('loading');
  const [lastUpdatedAt, setLastUpdatedAt] = useState<number | null>(null);
  const [missingContracts, setMissingContracts] = useState<string[]>([]);
  const [fetchSource, setFetchSource] = useState<'network' | 'cache' | null>(null);

  const requiredContractKey = useMemo(
    () => requiredContracts.join('|'),
    [requiredContracts],
  );

  const syncRegistry = useCallback(async (isManualRefresh = false) => {
    setStatus(isManualRefresh ? 'refreshing' : 'loading');
    setError(null);
    setMissingContracts([]);

    try {
      const result = await ContractRegistryService.sync(backendUrl);
      const requiredContractNames = requiredContractKey ? requiredContractKey.split('|') : [];
      const missing = requiredContractNames.filter(c => !result.registry[c]);

      setLastUpdatedAt(result.fetchedAt);
      setFetchSource(result.source);

      if (missing.length > 0) {
        setIsReady(false);
        setMissingContracts(missing);
        setStatus('incompatible');
        setError(`Missing contract definitions: ${missing.join(', ')}`);
        return;
      }

      setIsReady(true);
      setStatus(result.isStale ? 'stale' : 'ready');
      setError(
        result.isStale
          ? 'Using stale contract metadata. Refresh the registry before paying.'
          : null,
      );
    } catch (err) {
      setIsReady(false);
      setStatus('unavailable');
      setFetchSource(null);
      setError(err instanceof Error ? err.message : 'Registry unavailable');
    }
  }, [backendUrl, requiredContractKey]);

  useEffect(() => {
    void syncRegistry(false);
  }, [syncRegistry]);

  return {
    isReady,
    error,
    status,
    lastUpdatedAt,
    lastUpdatedLabel: formatLastUpdated(lastUpdatedAt),
    missingContracts,
    fetchSource,
    isRefreshing: status === 'refreshing',
    refresh: () => syncRegistry(true),
  };
}
