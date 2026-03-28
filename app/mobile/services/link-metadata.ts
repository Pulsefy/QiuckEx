import Constants from 'expo-constants';

/**
 * Base URL for the QuickEx backend.
 * Set EXPO_PUBLIC_API_URL in your .env file.
 * Falls back to localhost for local development.
 */
const API_BASE_URL =
    (Constants.expoConfig?.extra?.apiUrl as string | undefined) ??
    process.env['EXPO_PUBLIC_API_URL'] ??
    'http://localhost:3000';

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
