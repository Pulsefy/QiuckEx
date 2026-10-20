import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { fetchListings, type FetchListingsResponse } from "@/hooks/marketplaceApi";

describe("fetchListings - backend failure handling", () => {
  const originalFetch = global.fetch;

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    global.fetch = originalFetch;
  });

  it("returns degraded: true with empty listings on network failure", async () => {
    const fetchMock = vi.fn().mockRejectedValue(new Error("Network connection refused"));
    global.fetch = fetchMock;

    const result: FetchListingsResponse = await fetchListings({ bypassCache: true });

    expect(result.listings).toEqual([]);
    expect(result.degraded).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("returns degraded: true with empty listings on HTTP error", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: false,
      status: 500,
      json: async () => ({ error: "Internal Server Error" }),
    });
    global.fetch = fetchMock;

    const result: FetchListingsResponse = await fetchListings({ bypassCache: true });

    expect(result.listings).toEqual([]);
    expect(result.degraded).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("returns degraded: false with listings on successful fetch", async () => {
    const mockListings = [
      {
        id: "1",
        username: "test",
        seller_public_key: "GABC...XYZ",
        asking_price: 100,
        status: "active" as const,
        created_at: "2026-01-01T00:00:00.000Z",
        updated_at: "2026-01-01T00:00:00.000Z",
        sold_at: null,
        buyer_public_key: null,
        final_price: null,
      },
    ];

    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        listings: mockListings,
        total: 1,
        next_cursor: null,
        has_more: false,
      }),
    });
    global.fetch = fetchMock;

    const result: FetchListingsResponse = await fetchListings({ bypassCache: true });

    expect(result.listings).toHaveLength(1);
    expect(result.listings[0].username).toBe("test");
    expect(result.degraded).toBe(false);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("uses cached data when bypassCache is false and cache exists", async () => {
    const fetchMock = vi.fn();
    global.fetch = fetchMock;

    // First call to populate cache
    const mockListings = [
      {
        id: "1",
        username: "cached",
        seller_public_key: "GABC...XYZ",
        asking_price: 100,
        status: "active" as const,
        created_at: "2026-01-01T00:00:00.000Z",
        updated_at: "2026-01-01T00:00:00.000Z",
        sold_at: null,
        buyer_public_key: null,
        final_price: null,
      },
    ];

    const successMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        listings: mockListings,
        total: 1,
        next_cursor: null,
        has_more: false,
      }),
    });
    global.fetch = successMock;

    await fetchListings({ bypassCache: true });

    // Second call without bypassCache should use cache
    const cachedResult = await fetchListings({ bypassCache: false });

    expect(cachedResult.listings).toHaveLength(1);
    expect(cachedResult.listings[0].username).toBe("cached");
    expect(cachedResult.degraded).toBe(false);
    // Should not call fetch again
    expect(successMock).toHaveBeenCalledTimes(1);
  });
});
