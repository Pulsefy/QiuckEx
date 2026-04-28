import { useState, useCallback, useRef, useEffect } from 'react';
import NetInfo from '@react-native-community/netinfo';
import type { TransactionItem, TransactionResponse } from '../types/transaction';
import { fetchTransactions } from '../services/transactions';
import { getTransactionsFromCache, saveTransactionsToCache } from '../services/cache';

interface UseTransactionsState {
    transactions: TransactionItem[];
    loading: boolean;
    refreshing: boolean;
    error: string | null;
    hasMore: boolean;
}

interface UseTransactionsReturn extends UseTransactionsState {
    refresh: () => void;
    loadMore: () => void;
}

/**
 * Custom hook that manages fetching, paginating, and refreshing transactions
 * for a given Stellar accountId.
 */
export function useTransactions(accountId: string): UseTransactionsReturn {
    const [state, setState] = useState<UseTransactionsState>({
        transactions: [],
        loading: true,
        refreshing: false,
        error: null,
        hasMore: false,
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
                            transactions: cachedData.items,
                            loading: false,
                            refreshing: false,
                            error: null,
                            hasMore: !!cachedData.nextCursor,
                        });
                        nextCursorRef.current = cachedData.nextCursor;
                        return;
                    }
                }

                setState((prev) => ({
                    ...prev,
                    loading: false,
                    refreshing: false,
                    error: 'You are currently offline. Please check your connection and try again.',
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
                });

                nextCursorRef.current = data.nextCursor;

                // Save to cache on successful reset fetch (first page)
                if (reset) {
                    void saveTransactionsToCache(accountId, data);
                }

                setState((prev: UseTransactionsState) => ({
                    transactions: reset ? data.items : [...prev.transactions, ...data.items],
                    loading: false,
                    refreshing: false,
                    error: null,
                    hasMore: !!data.nextCursor,
                }));
            } catch (err) {
                // If fetching fails, try to fall back to cache for the first page
                if (reset) {
                    const cachedData = await getTransactionsFromCache(accountId);
                    if (cachedData) {
                        setState({
                            transactions: cachedData.items,
                            loading: false,
                            refreshing: false,
                            error: null,
                            hasMore: !!cachedData.nextCursor,
                        });
                        nextCursorRef.current = cachedData.nextCursor;
                        return;
                    }
                }

                const message =
                    err instanceof Error ? err.message : 'An unexpected error occurred.';
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
        [accountId],
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
