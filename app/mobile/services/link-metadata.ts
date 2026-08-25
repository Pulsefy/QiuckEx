import { API_URL } from '../src/config/build';

/**
 * Base URL for the QuickEx backend.
 *
 * Resolved from the shared {@link API_URL} constant in `src/config/build`,
 * which is set at build time from app.config.ts and falls back to
 * `EXPO_PUBLIC_API_URL` or `http://localhost:4000` for local dev.
 */
const API_BASE_URL = API_URL;

export interface PathPreviewRow {
  sourceAmount: string;
  sourceAsset: string;
  destinationAmount: string;
  destinationAsset: string;
  hopCount: number;
  pathHops: string[];
  rateDescription: string;
}

export interface LinkMetadataResponse {
  amount: string;
  memo: string | null;
  memoType: string;
  asset: string;
  privacy: boolean;
  expiresAt: string | null;
  canonical: string;
  username?: string | null;
  destination?: string | null;
  referenceId?: string | null;
  acceptedAssets?: string[] | null;
  swapOptions?: PathPreviewRow[] | null;
  metadata: {
    normalized: boolean;
    warnings?: string[];
    [key: string]: unknown;
  };
}

export interface FetchLinkMetadataOptions {
  acceptedAssets?: string[];
}

/**
 * Fetches link metadata with optional swap options from the QuickEx backend.
 * Throws a descriptive Error on network issues or non-2xx responses.
 */
export async function fetchLinkMetadata(
  username: string,
  amount: number,
  asset: string,
  options: FetchLinkMetadataOptions = {},
): Promise<LinkMetadataResponse> {
  const { acceptedAssets } = options;

  const requestBody = {
    amount,
    asset,
    username,
  };

  // Only include acceptedAssets if provided (enables swap path preview)
  if (acceptedAssets && acceptedAssets.length > 0) {
    Object.assign(requestBody, { acceptedAssets });
  }

  const url = `${API_BASE_URL}/links/metadata`;

  let response: Response;
  try {
    response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify(requestBody),
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

  return response.json() as Promise<LinkMetadataResponse>;
}
