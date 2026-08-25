import { API_URL } from '../src/config/build';
import type { TransactionResponse } from '../types/transaction';

/**
 * Base URL for the QuickEx backend.
 *
 * Resolved from the shared {@link API_URL} constant in `src/config/build`,
 * which is set at build time from app.config.ts and falls back to
 * `EXPO_PUBLIC_API_URL` or `http://localhost:4000` for local dev.
 */
const API_BASE_URL = API_URL;

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
