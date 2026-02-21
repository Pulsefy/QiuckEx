import Constants from 'expo-constants';
import type { TransactionResponse } from '../types/transaction';

/**
 * Base URL for the QuickEx backend.
 * Set EXPO_PUBLIC_API_URL in your .env file.
 * Falls back to localhost for local development.
 */
const API_BASE_URL =
    (Constants.expoConfig?.extra?.apiUrl as string | undefined) ??
    process.env['EXPO_PUBLIC_API_URL'] ??
    'http://localhost:3000';

export interface FetchTransactionsOptions {
    limit?: number;
    cursor?: string;
    asset?: string;
}

/**
 * Fetches paginated payment history for a Stellar account from the QuickEx backend.
 * Throws a descriptive Error on network issues or non-2xx responses.
 */
export async function fetchTransactions(
    accountId: string,
    options: FetchTransactionsOptions = {},
): Promise<TransactionResponse> {
    const { limit = 20, cursor, asset } = options;

    const params = new URLSearchParams({ accountId, limit: String(limit) });
    if (cursor) params.set('cursor', cursor);
    if (asset) params.set('asset', asset);

    const url = `${API_BASE_URL}/transactions?${params.toString()}`;

    let response: Response;
    try {
        response = await fetch(url, {
            headers: { Accept: 'application/json' },
        });
    } catch (networkError) {
        throw new Error('Network request failed. Check your connection and try again.');
    }

    if (!response.ok) {
        let message = `Server error (${response.status})`;
        try {
            const body = (await response.json()) as { message?: string };
            if (body.message) message = body.message;
        } catch {
            // ignore JSON parse errors — keep the status-code message
        }
        throw new Error(message);
    }

    return response.json() as Promise<TransactionResponse>;
}
