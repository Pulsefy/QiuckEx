import { getQuickexApiBase } from "@/lib/api";

export type DiscoveryResultKind = "profile" | "listing";

/**
 * Mirrors the backend `SearchDiscoveryResultDto`
 * (app/backend/src/dto/username/search-usernames-response.dto.ts).
 */
export type SearchDiscoveryResult = {
  kind: DiscoveryResultKind;
  id: string;
  username: string;
  publicKey?: string;
  sellerPublicKey?: string;
  similarityScore?: number;
  askingPrice?: number;
  status?: string;
  lastActiveAt?: string;
  createdAt: string;
};

/**
 * Mirrors the backend `SearchUsernamesResponseDto` returned by
 * GET /username/search — the single shared search contract used across
 * all discovery surfaces.
 */
export type DiscoverySearchResponse = {
  results: SearchDiscoveryResult[];
  empty: boolean;
  total: number;
  next_cursor: string | null;
  has_more: boolean;
};

export type GroupedDiscoveryResults = {
  profiles: SearchDiscoveryResult[];
  listings: SearchDiscoveryResult[];
  response: DiscoverySearchResponse;
};

/** Backend rejects queries shorter than this. */
export const MIN_SEARCH_LENGTH = 2;

const SEARCH_ENDPOINT = "/username/search";

export function buildDiscoverySearchParams(
  query: string,
  limit?: number,
  cursor?: string
): URLSearchParams {
  const params = new URLSearchParams({ query });
  if (typeof limit === "number" && Number.isFinite(limit)) {
    params.set("limit", String(limit));
  }
  if (cursor) {
    params.set("cursor", cursor);
  }
  return params;
}

/**
 * Runs a unified discovery search against the shared backend contract.
 * Results come back grouped by kind so consumers can render labeled
 * sections without re-filtering.
 */
export async function searchDiscovery(
  query: string,
  options: { limit?: number; cursor?: string; signal?: AbortSignal } = {}
): Promise<GroupedDiscoveryResults> {
  const res = await fetch(
    `${getQuickexApiBase()}${SEARCH_ENDPOINT}?${buildDiscoverySearchParams(
      query,
      options.limit,
      options.cursor
    ).toString()}`,
    {
      signal: options.signal,
      headers: { Accept: "application/json" },
    }
  );

  if (!res.ok) {
    throw new Error(`Discovery search failed with status ${res.status}`);
  }

  const response = (await res.json()) as DiscoverySearchResponse;

  return {
    profiles: response.results.filter((r) => r.kind === "profile"),
    listings: response.results.filter((r) => r.kind === "listing"),
    response,
  };
}
