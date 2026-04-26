import AsyncStorage from '@react-native-async-storage/async-storage';
import type { TransactionResponse } from '../types/transaction';

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
 * Simple cache invalidation: clears data older than 7 days.
 */
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
