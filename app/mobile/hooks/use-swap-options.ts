import { useState, useCallback, useEffect } from 'react';
import NetInfo from '@react-native-community/netinfo';
import { fetchLinkMetadata, type LinkMetadataResponse, type PathPreviewRow, type FetchLinkMetadataOptions } from '../services/link-metadata';

interface UseSwapOptionsState {
  metadata: LinkMetadataResponse | null;
  loading: boolean;
  error: string | null;
  swapOptions: PathPreviewRow[] | null;
  timeRemaining: number; // in seconds
  isExpired: boolean;
}

interface UseSwapOptionsReturn extends UseSwapOptionsState {
  refetch: () => Promise<void>;
}

const QUOTE_EXPIRY_SECONDS = 60;

/**
 * Custom hook that fetches link metadata with optional swap path options.
 * Automatically fetches available assets that can be used to pay the link.
 * Includes quote expiry and countdown logic.
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
    timeRemaining: QUOTE_EXPIRY_SECONDS,
    isExpired: false,
  });

  const fetch = useCallback(async () => {
    setState((prev) => ({ ...prev, loading: true, error: null, isExpired: false, timeRemaining: QUOTE_EXPIRY_SECONDS }));

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

      // Check if we have swap options, otherwise it might mean no path found
      const hasSwapOptions = metadata.swapOptions && metadata.swapOptions.length > 0;
      
      setState((prev) => ({
        ...prev,
        loading: false,
        metadata,
        swapOptions: metadata.swapOptions || null,
        error: !hasSwapOptions && acceptedAssets && acceptedAssets.length > 0 
          ? 'No suitable payment paths found for the selected assets. Liquidity may be insufficient.' 
          : null,
      }));
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to fetch payment options';
      setState((prev) => ({ ...prev, loading: false, error: errorMessage }));
    }
  }, [username, amount, asset, acceptedAssets]);

  useEffect(() => {
    void fetch();
  }, [fetch]);

  // Countdown timer logic
  useEffect(() => {
    if (state.loading || state.error || !state.swapOptions) return;

    const timer = setInterval(() => {
      setState((prev) => {
        if (prev.timeRemaining <= 1) {
          clearInterval(timer);
          return { ...prev, timeRemaining: 0, isExpired: true };
        }
        return { ...prev, timeRemaining: prev.timeRemaining - 1 };
      });
    }, 1000);

    return () => clearInterval(timer);
  }, [state.loading, state.error, state.swapOptions]);

  const refetch = useCallback(async () => {
    await fetch();
  }, [fetch]);

  return { ...state, refetch };
}
