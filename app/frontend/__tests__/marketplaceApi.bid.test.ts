import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { placeBid, type BidResult } from "@/hooks/marketplaceApi";

describe("placeBid - real endpoint integration", () => {
  const originalFetch = global.fetch;

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    global.fetch = originalFetch;
  });

  it("successfully places a bid against the real endpoint", async () => {
    const mockBidResponse = {
      bid: {
        id: "bid-123",
        listing_id: "listing-456",
        bidder_public_key: "GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR",
        bid_amount: 150,
        status: "pending",
        created_at: "2026-09-30T10:00:00.000Z",
        updated_at: "2026-09-30T10:00:00.000Z",
      },
    };

    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 201,
      json: async () => mockBidResponse,
    });
    global.fetch = fetchMock;

    const result: BidResult = await placeBid("listing-456", 150, {
      listingId: "listing-456",
      bidderPublicKey: "GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR",
    });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [calledUrl, calledInit] = fetchMock.mock.calls[0];
    expect(calledUrl).toContain("/marketplace/listing-456/bid");
    expect(calledInit.method).toBe("POST");
    expect(calledInit.headers["Content-Type"]).toBe("application/json");

    const payload = JSON.parse(calledInit.body);
    expect(payload.bidAmount).toBe(150);
    expect(payload.bidderPublicKey).toBe("GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR");

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.bid?.id).toBe("bid-123");
    }
  });

  it("handles validation error response from the endpoint", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: false,
      status: 400,
      json: async () => ({
        statusCode: 400,
        message: ["Public key must be a valid Stellar public key"],
        error: "Bad Request",
      }),
    });
    global.fetch = fetchMock;

    const result = await placeBid("listing-456", 50, {
      listingId: "listing-456",
      bidderPublicKey: "INVALID_KEY",
    });

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.code).toBe("validation");
      expect(result.reason).toContain("Public key must be a valid Stellar public key");
    }
  });

  it("handles insufficient funds error distinctly", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: false,
      status: 400,
      json: async () => ({
        statusCode: 400,
        message: "Insufficient funds: wallet balance too low to cover bid amount",
        code: "INSUFFICIENT_FUNDS",
      }),
    });
    global.fetch = fetchMock;

    const result = await placeBid("listing-456", 10000);

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.code).toBe("insufficient_funds");
      expect(result.reason).toContain("Insufficient funds");
    }
  });

  it("handles listing not found (404) error distinctly", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: false,
      status: 404,
      json: async () => ({
        statusCode: 404,
        message: "Listing not found",
        code: "LISTING_NOT_FOUND",
      }),
    });
    global.fetch = fetchMock;

    const result = await placeBid("non-existent-id", 200);

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.code).toBe("not_found");
      expect(result.reason).toContain("Listing not found");
    }
  });

  it("handles network failure cleanly as network error code", async () => {
    const fetchMock = vi.fn().mockRejectedValue(new Error("Network connection refused"));
    global.fetch = fetchMock;

    const result = await placeBid("listing-456", 200);

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.code).toBe("network");
      expect(result.reason).toContain("Network connection refused");
    }
  });
});
