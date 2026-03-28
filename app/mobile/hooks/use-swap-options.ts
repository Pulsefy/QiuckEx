import { useState, useCallback, useEffect } from 'react';
import NetInfo from '@react-native-community/netinfo';
import { fetchLinkMetadata, type LinkMetadataResponse, type PathPreviewRow, type FetchLinkMetadataOptions } from '../services/link-metadata';

interface UseSwapOptionsState {
  metadata: LinkMetadataResponse | null;
  loading: boolean;
  error: string | null;
  swapOptions: PathPreviewRow[] | null;
}

interface UseSwapOptionsReturn extends UseSwapOptionsState {
  refetch: () => Promise<void>;
}

/**
 * Custom hook that fetches link metadata with optional swap path options.
 * Automatically fetches available assets that can be used to pay the link.
 */
export function useSwapOptions(
  username: string,
  amount: number,
  asset: string,
  acceptedAssets?: string[],
): UseSwapOptionsReturn {
  const [state, setState] = useState<UseSwapOptionsState>({
    metadata: null,
    loading: true,
    error: null,
    swapOptions: null,
  });

  const fetch = useCallback(async () => {
    setState((prev) => ({ ...prev, loading: true, error: null }));

    try {
      // Check connectivity first
      const netInfo = await NetInfo.fetch();
      if (!netInfo.isConnected) {
        setState((prev) => ({
          ...prev,
          loading: false,
          error: 'You are currently offline. Please check your connection and try again.',
        }));
        return;
      }

      // Only fetch swap options if acceptedAssets are provided
      const options: FetchLinkMetadataOptions = {};
      if (acceptedAssets && acceptedAssets.length > 0) {
        options.acceptedAssets = acceptedAssets;
      }

      const metadata = await fetchLinkMetadata(username, amount, asset, options);

      setState((prev) => ({
        ...prev,
        loading: false,
        metadata,
        swapOptions: metadata.swapOptions || null,
      }));
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to fetch payment options';
      setState((prev) => ({ ...prev, loading: false, error: errorMessage }));
    }
  }, [username, amount, asset, acceptedAssets]);

  useEffect(() => {
    void fetch();
  }, [fetch]);

  const refetch = useCallback(async () => {
    await fetch();
  }, [fetch]);

  return { ...state, refetch };
}
