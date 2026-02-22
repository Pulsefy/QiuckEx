import { useState, useCallback, useRef, useEffect } from 'react';
import NetInfo from '@react-native-community/netinfo';
import type { TransactionItem } from '../types/transaction';
import { fetchTransactions } from '../services/transactions';

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
            if (!netInfo.isConnected) {
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

                setState((prev: UseTransactionsState) => ({
                    transactions: reset ? data.items : [...prev.transactions, ...data.items],
                    loading: false,
                    refreshing: false,
                    error: null,
                    hasMore: !!data.nextCursor,
                }));
            } catch (err) {
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
