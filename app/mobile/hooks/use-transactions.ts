import { useState, useCallback, useRef, useEffect } from "react";
import NetInfo from "@react-native-community/netinfo";
import type {
  TransactionItem,
  TransactionResponse,
} from "../types/transaction";
import { fetchTransactions } from "../services/transactions";
import {
  getTransactionsFromCache,
  saveTransactionsToCache,
} from "../services/cache";

interface UseTransactionsState {
  transactions: TransactionItem[];
  loading: boolean;
  refreshing: boolean;
  error: string | null;
  hasMore: boolean;
  /**
   * True when the displayed data comes from cache rather than a live backend response.
   * The screen can show a "Showing cached data" banner when this is true.
   */
  staleCache: boolean;
}

interface UseTransactionsReturn extends UseTransactionsState {
  refresh: () => void;
  loadMore: () => void;
}

/**
 * Annotate each transaction item with a direction relative to the connected account.
 * 'sent' when the source matches the account, 'received' otherwise.
 */
function withDirection(
  items: TransactionItem[],
  accountId: string,
): TransactionItem[] {
  return items.map((item) => ({
    ...item,
    direction:
      item.source?.toLowerCase() === accountId.toLowerCase()
        ? "sent"
        : "received",
  }));
}

/**
 * Custom hook that manages fetching, paginating, and refreshing transactions
 * for a given Stellar accountId.
 *
 * Supports:
 * - Server-side asset filtering (passed to the backend for efficient queries)
 * - Cursor-based pagination (loadMore)
 * - Pull-to-refresh (refresh)
 * - Offline cache fallback with stale-data indicator
 * - Payment direction derivation (sent/received)
 */
export function useTransactions(
  accountId: string,
  options?: { asset?: string },
): UseTransactionsReturn {
  const [state, setState] = useState<UseTransactionsState>({
    transactions: [],
    loading: true,
    refreshing: false,
    error: null,
    hasMore: false,
    staleCache: false,
  });

  const nextCursorRef = useRef<string | undefined>(undefined);
  const isFetchingRef = useRef(false);

  const load = useCallback(
    async (opts: { reset?: boolean; isRefreshing?: boolean } = {}) => {
      const { reset = false, isRefreshing = false } = opts;

      if (isFetchingRef.current) return;

      // Fast check for connectivity
      const netInfo = await NetInfo.fetch();
      if (netInfo.isConnected === false) {
        // Try to load from cache if offline
        if (reset) {
          const cachedData = await getTransactionsFromCache(accountId);
          if (cachedData) {
            setState({
              transactions: withDirection(cachedData.items, accountId),
              loading: false,
              refreshing: false,
              error: null,
              hasMore: !!cachedData.nextCursor,
              staleCache: true,
            });
            nextCursorRef.current = cachedData.nextCursor;
            return;
          }
        }

        setState((prev) => ({
          ...prev,
          loading: false,
          refreshing: false,
          error:
            "You are currently offline. Please check your connection and try again.",
        }));
        return;
      }

      isFetchingRef.current = true;

      if (reset) {
        nextCursorRef.current = undefined;
      }

      setState((prev: UseTransactionsState) => ({
        ...prev,
        loading: reset && !isRefreshing,
        refreshing: isRefreshing,
        error: null,
      }));

      try {
        const data = await fetchTransactions(accountId, {
          cursor: reset ? undefined : nextCursorRef.current,
          asset: options?.asset,
        });

        nextCursorRef.current = data.nextCursor;

        // Save to cache on successful reset fetch (first page)
        if (reset) {
          void saveTransactionsToCache(accountId, data);
        }

        setState((prev: UseTransactionsState) => {
          const incoming = withDirection(data.items, accountId);

          if (reset) {
            return {
              transactions: incoming,
              loading: false,
              refreshing: false,
              error: null,
              hasMore: !!data.nextCursor,
              staleCache: false,
            };
          }

          // Dedup by pagingToken so overlapping pages from live feeds/refresh
          // never accumulate duplicates, keeping memory bounded as history grows.
          const seen = new Set(prev.transactions.map((t) => t.pagingToken));
          const merged = [
            ...prev.transactions,
            ...incoming.filter((t) => !seen.has(t.pagingToken)),
          ];

          return {
            transactions: merged,
            loading: false,
            refreshing: false,
            error: null,
            hasMore: !!data.nextCursor,
            staleCache: false,
          };
        });
      } catch (err) {
        // If fetching fails, try to fall back to cache for the first page
        if (reset) {
          const cachedData = await getTransactionsFromCache(accountId);
          if (cachedData) {
            setState({
              transactions: withDirection(cachedData.items, accountId),
              loading: false,
              refreshing: false,
              error: null,
              hasMore: !!cachedData.nextCursor,
              staleCache: true,
            });
            nextCursorRef.current = cachedData.nextCursor;
            return;
          }
        }

        const message =
          err instanceof Error ? err.message : "An unexpected error occurred.";
        setState((prev: UseTransactionsState) => ({
          ...prev,
          loading: false,
          refreshing: false,
          error: message,
        }));
      } finally {
        isFetchingRef.current = false;
      }
    },
    [accountId, options?.asset],
  );

  // Initial load
  useEffect(() => {
    void load({ reset: true });
  }, [load]);

  const refresh = useCallback(() => {
    void load({ reset: true, isRefreshing: true });
  }, [load]);

  const loadMore = useCallback(() => {
    if (state.hasMore && !isFetchingRef.current) {
      void load();
    }
  }, [load, state.hasMore]);

  return { ...state, refresh, loadMore };
}
