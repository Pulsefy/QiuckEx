import { describe, expect, it, beforeEach, afterEach, vi } from "vitest";

import {
  fetchListings,
  fetchUserBids,
  fetchUserListings,
  clearMarketplaceCache,
  type BackendMarketplaceListing,
} from "@/hooks/marketplaceApi";

describe("marketplaceApi fetch functions without mock fallbacks (FE-58)", () => {
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    clearMarketplaceCache();
    vi.restoreAllMocks();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    clearMarketplaceCache();
  });

  describe("fetchListings", () => {
    it("returns mapped listings on successful API response", async () => {
      const mockBackendListings: BackendMarketplaceListing[] = [
        {
          id: "listing-abc",
          username: "crypto",
          seller_public_key: "GA123456789012345678901234567890123456789012345678901234",
          asking_price: 5000,
          status: "active",
          created_at: "2026-08-01T10:00:00.000Z",
          updated_at: "2026-08-01T10:00:00.000Z",
          sold_at: null,
          buyer_public_key: null,
          final_price: null,
        },
      ];

      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({
          listings: mockBackendListings,
          total: 1,
          next_cursor: null,
          has_more: false,
        }),
      });

      const listings = await fetchListings({ bypassCache: true });

      expect(listings).toHaveLength(1);
      expect(listings[0].id).toBe("listing-abc");
      expect(listings[0].username).toBe("crypto");
      expect(listings[0].currentBid).toBe(5000);
      expect(listings[0].status).toBe("auction");
    });

    it("returns empty array on empty API response (not mock listings)", async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({
          listings: [],
          total: 0,
          next_cursor: null,
          has_more: false,
        }),
      });

      const listings = await fetchListings({ bypassCache: true });

      expect(listings).toEqual([]);
      expect(listings).toHaveLength(0);
    });

    it("throws an error on API error response (500) and does not fall back to mock data", async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 500,
        statusText: "Internal Server Error",
      });

      await expect(fetchListings({ bypassCache: true })).rejects.toThrow(
        /Failed to load marketplace listings \(500\)/,
      );
    });

    it("throws an error on API error response (404) and does not fall back to mock data", async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 404,
        statusText: "Not Found",
      });

      await expect(fetchListings({ bypassCache: true })).rejects.toThrow(
        /Failed to load marketplace listings \(404\)/,
      );
    });

    it("throws on network failure (fetch rejection) and does not fall back to mock data", async () => {
      globalThis.fetch = vi.fn().mockRejectedValue(new Error("Network connection lost"));

      await expect(fetchListings({ bypassCache: true })).rejects.toThrow(
        "Network connection lost",
      );
    });
  });

  describe("fetchUserBids", () => {
    it("returns empty array instead of mock bids when no cached user bids exist", async () => {
      const bids = await fetchUserBids();
      expect(bids).toEqual([]);
      expect(bids).toHaveLength(0);
    });
  });

  describe("fetchUserListings", () => {
    it("returns empty array instead of mock listings when no cached user listings exist", async () => {
      const userListings = await fetchUserListings();
      expect(userListings).toEqual([]);
      expect(userListings).toHaveLength(0);
    });
  });
});
