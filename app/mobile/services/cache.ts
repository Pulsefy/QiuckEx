import AsyncStorage from '@react-native-async-storage/async-storage';
import type { TransactionItem, TransactionResponse } from '../types/transaction';

const TRANSACTIONS_CACHE_KEY_PREFIX = '@qex_tx_cache_';
const PROFILE_CACHE_KEY_PREFIX = '@qex_profile_cache_';

/**
 * Saves transactions for a specific account to the local cache.
 */
export async function saveTransactionsToCache(accountId: string, data: TransactionResponse): Promise<void> {
    try {
        const cacheEntry = {
            data,
            timestamp: Date.now(),
        };
        await AsyncStorage.setItem(`${TRANSACTIONS_CACHE_KEY_PREFIX}${accountId}`, JSON.stringify(cacheEntry));
    } catch (err) {
        console.error('Failed to save transactions to cache', err);
    }
}

/**
 * Retrieves cached transactions for a specific account.
 * Returns null if no cache is found.
 */
export async function getTransactionsFromCache(accountId: string): Promise<TransactionResponse | null> {
    try {
        const raw = await AsyncStorage.getItem(`${TRANSACTIONS_CACHE_KEY_PREFIX}${accountId}`);
        if (!raw) return null;
        
        const entry = JSON.parse(raw);
        return entry.data;
    } catch (err) {
        console.error('Failed to get transactions from cache', err);
        return null;
    }
}

/**
 * Searches all cached transaction responses for a specific transaction by pagingToken.
 * Returns the matching TransactionItem or null if not found.
 */
export async function findTransactionInCache(
    pagingToken: string,
): Promise<TransactionItem | null> {
    try {
        const keys = await AsyncStorage.getAllKeys();
        const cacheKeys = keys.filter((k) =>
            k.startsWith(TRANSACTIONS_CACHE_KEY_PREFIX),
        );

        for (const key of cacheKeys) {
            const raw = await AsyncStorage.getItem(key);
            if (!raw) continue;
            const entry = JSON.parse(raw) as {
                data: TransactionResponse;
                timestamp: number;
            };
            const match = entry.data.items.find(
                (item) => item.pagingToken === pagingToken,
            );
            if (match) return match;
        }
        
        // Also check standalone individual cache entries
        const standaloneKey = `${TRANSACTIONS_CACHE_KEY_PREFIX}individual_${pagingToken}`;
        const standaloneRaw = await AsyncStorage.getItem(standaloneKey);
        if (standaloneRaw) {
            const entry = JSON.parse(standaloneRaw) as {
                data: TransactionResponse;
                timestamp: number;
            };
            if (entry.data.items.length > 0) {
                return entry.data.items[0];
            }
        }
        
        return null;
    } catch (err) {
        console.error('Failed to find transaction in cache', err);
        return null;
    }
}

/**
 * Saves a single transaction to the local cache.
 * This is used when fetching a receipt from the API to enable offline viewing.
 */
export async function saveTransactionToCache(
    transaction: TransactionItem,
): Promise<void> {
    try {
        // Find all existing cache entries to see if this transaction belongs to any account
        const keys = await AsyncStorage.getAllKeys();
        const cacheKeys = keys.filter((k) =>
            k.startsWith(TRANSACTIONS_CACHE_KEY_PREFIX),
        );

        // Try to find the account this transaction belongs to by checking cached data
        for (const key of cacheKeys) {
            const raw = await AsyncStorage.getItem(key);
            if (!raw) continue;
            
            const entry = JSON.parse(raw) as {
                data: TransactionResponse;
                timestamp: number;
            };
            
            // Check if this transaction already exists in this account's cache
            const existingIndex = entry.data.items.findIndex(
                (item) => item.pagingToken === transaction.pagingToken,
            );
            
            if (existingIndex !== -1) {
                // Update existing transaction
                entry.data.items[existingIndex] = transaction;
                await AsyncStorage.setItem(key, JSON.stringify(entry));
                return;
            }
            
            // If the transaction source or destination matches the account ID (derived from key),
            // add it to that account's cache
            const accountId = key.replace(TRANSACTIONS_CACHE_KEY_PREFIX, '');
            if (transaction.source === accountId || transaction.destination === accountId) {
                entry.data.items.unshift(transaction);
                await AsyncStorage.setItem(key, JSON.stringify(entry));
                return;
            }
        }
        
        // If no matching account cache found, create a standalone cache entry
        // using the transaction's pagingToken as the key
        const standaloneKey = `${TRANSACTIONS_CACHE_KEY_PREFIX}individual_${transaction.pagingToken}`;
        const cacheEntry = {
            data: {
                items: [transaction],
            },
            timestamp: Date.now(),
        };
        await AsyncStorage.setItem(standaloneKey, JSON.stringify(cacheEntry));
    } catch (err) {
        console.error('Failed to save transaction to cache', err);
    }
}

export async function invalidateOldCache(): Promise<void> {
    try {
        const keys = await AsyncStorage.getAllKeys();
        const cacheKeys = keys.filter(k => k.startsWith(TRANSACTIONS_CACHE_KEY_PREFIX) || k.startsWith(PROFILE_CACHE_KEY_PREFIX));
        
        const now = Date.now();
        const sevenDaysMs = 7 * 24 * 60 * 60 * 1000;
        
        for (const key of cacheKeys) {
            const raw = await AsyncStorage.getItem(key);
            if (raw) {
                const entry = JSON.parse(raw);
                if (now - entry.timestamp > sevenDaysMs) {
                    await AsyncStorage.removeItem(key);
                }
            }
        }
    } catch (err) {
        console.error('Failed to invalidate old cache', err);
    }
}
