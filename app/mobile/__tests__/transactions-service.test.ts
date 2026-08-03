/**
 * Unit tests for the transactions service.
 *
 * Tests cover:
 * - Successful fetch with correct URL construction
 * - Pagination (cursor parameter)
 * - Asset filtering
 * - Network error handling
 * - HTTP error handling (4xx, 5xx)
 * - JSON parse error resilience
 */

import { fetchTransactions } from "../services/transactions";

// Mock global fetch
const mockFetch = jest.fn();
global.fetch = mockFetch;

const ACCOUNT_ID = "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN";
const BASE_URL = "http://localhost:3000";

const mockTransactionResponse = {
  items: [
    {
      amount: "50.0000000",
      asset: "USDC:GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN",
      memo: "Payment for services",
      timestamp: "2026-06-01T10:00:00Z",
      source: ACCOUNT_ID,
      destination: "GBDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVWXYZ2",
      status: "Success" as const,
      txHash:
        "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
      pagingToken: "12345678-1-0",
    },
  ],
  nextCursor: "12345678-1-0",
};

describe("fetchTransactions", () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  it("fetches transactions with the correct URL", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => mockTransactionResponse,
    });

    await fetchTransactions(ACCOUNT_ID);

    expect(mockFetch).toHaveBeenCalledTimes(1);
    const url = mockFetch.mock.calls[0][0] as string;
    expect(url).toContain("/transactions?");
    expect(url).toContain(`accountId=${ACCOUNT_ID}`);
    expect(url).toContain("limit=20");
  });

  it("includes cursor parameter when provided", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => mockTransactionResponse,
    });

    await fetchTransactions(ACCOUNT_ID, { cursor: "some-cursor" });

    const url = mockFetch.mock.calls[0][0] as string;
    expect(url).toContain("cursor=some-cursor");
  });

  it("includes asset parameter when provided", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => mockTransactionResponse,
    });

    await fetchTransactions(ACCOUNT_ID, { asset: "USDC" });

    const url = mockFetch.mock.calls[0][0] as string;
    expect(url).toContain("asset=USDC");
  });

  it("uses custom limit", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => mockTransactionResponse,
    });

    await fetchTransactions(ACCOUNT_ID, { limit: 50 });

    const url = mockFetch.mock.calls[0][0] as string;
    expect(url).toContain("limit=50");
  });

  it("returns the parsed JSON response", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => mockTransactionResponse,
    });

    const result = await fetchTransactions(ACCOUNT_ID);

    expect(result.items).toHaveLength(1);
    expect(result.items[0].amount).toBe("50.0000000");
    expect(result.nextCursor).toBe("12345678-1-0");
  });

  it("throws a network error message when fetch fails", async () => {
    mockFetch.mockRejectedValueOnce(new Error("Network timeout"));

    await expect(fetchTransactions(ACCOUNT_ID)).rejects.toThrow(
      "Network request failed. Check your connection and try again.",
    );
  });

  it("throws server error message on non-2xx response", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 500,
      json: async () => ({ message: "Internal server error" }),
    });

    await expect(fetchTransactions(ACCOUNT_ID)).rejects.toThrow(
      "Internal server error",
    );
  });

  it("falls back to status code message when JSON parse fails", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 502,
      json: async () => {
        throw new Error("Invalid JSON");
      },
    });

    await expect(fetchTransactions(ACCOUNT_ID)).rejects.toThrow(
      "Server error (502)",
    );
  });

  it("throws rate limit error on 429", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 429,
      json: async () => ({ message: "Rate limit exceeded" }),
    });

    await expect(fetchTransactions(ACCOUNT_ID)).rejects.toThrow(
      "Rate limit exceeded",
    );
  });

  it("sends Accept: application/json header", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => mockTransactionResponse,
    });

    await fetchTransactions(ACCOUNT_ID);

    const options = mockFetch.mock.calls[0][1];
    expect(options.headers).toEqual({ Accept: "application/json" });
  });

  it("handles empty items array", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ items: [], nextCursor: undefined }),
    });

    const result = await fetchTransactions(ACCOUNT_ID);

    expect(result.items).toHaveLength(0);
    expect(result.nextCursor).toBeUndefined();
  });
});
