/**
 * Unit tests for the useTransactions hook.
 *
 * Tests cover:
 * - Initial data fetch and state transitions
 * - Pagination (loadMore)
 * - Pull-to-refresh behavior
 * - Offline fallback to cache
 * - Payment direction derivation (sent/received)
 * - Stale cache flag
 * - Error handling with cache fallback
 * - Asset filter passthrough
 */

import { renderHook, act } from "@testing-library/react-native";
import { useTransactions } from "../hooks/use-transactions";
import { fetchTransactions } from "../services/transactions";
import {
  getTransactionsFromCache,
  saveTransactionsToCache,
} from "../services/cache";
import NetInfo from "@react-native-community/netinfo";

// Mock dependencies
jest.mock("../services/transactions");
jest.mock("../services/cache");
jest.mock("@react-native-community/netinfo", () => ({
  fetch: jest.fn(),
}));

const mockedFetchTransactions = fetchTransactions as jest.MockedFunction<
  typeof fetchTransactions
>;
const mockedGetCache = getTransactionsFromCache as jest.MockedFunction<
  typeof getTransactionsFromCache
>;
const mockedSaveCache = saveTransactionsToCache as jest.MockedFunction<
  typeof saveTransactionsToCache
>;
const mockedNetInfoFetch = NetInfo.fetch as jest.MockedFunction<
  typeof NetInfo.fetch
>;

const ACCOUNT_ID = "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN";
const OTHER_ACCOUNT =
  "GBDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVWXYZ2";

const mockItems = [
  {
    amount: "50.0000000",
    asset: "XLM",
    memo: "Test payment",
    timestamp: "2026-06-01T10:00:00Z",
    source: ACCOUNT_ID,
    destination: OTHER_ACCOUNT,
    status: "Success" as const,
    txHash: "abc123",
    pagingToken: "100-1-0",
  },
  {
    amount: "25.0000000",
    asset: "USDC",
    timestamp: "2026-06-01T09:00:00Z",
    source: OTHER_ACCOUNT,
    destination: ACCOUNT_ID,
    status: "Success" as const,
    txHash: "def456",
    pagingToken: "99-1-0",
  },
];

describe("useTransactions", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockedNetInfoFetch.mockResolvedValue({ isConnected: true } as any);
    mockedSaveCache.mockResolvedValue(undefined);
  });

  it("fetches transactions on mount and sets loading=false on success", async () => {
    mockedFetchTransactions.mockResolvedValueOnce({
      items: mockItems,
      nextCursor: "99-1-0",
    });

    const { result } = await renderHook(() => useTransactions(ACCOUNT_ID));

    // Wait for the fetch to complete
    await act(async () => {
      await new Promise((r) => setTimeout(r, 0));
    });

    expect(result.current.loading).toBe(false);
    expect(result.current.transactions).toHaveLength(2);
    expect(result.current.hasMore).toBe(true);
    expect(result.current.error).toBeNull();
    expect(result.current.staleCache).toBe(false);
  });

  it("derives payment direction for each transaction", async () => {
    mockedFetchTransactions.mockResolvedValueOnce({
      items: mockItems,
      nextCursor: undefined,
    });

    const { result } = await renderHook(() => useTransactions(ACCOUNT_ID));

    await act(async () => {
      await new Promise((r) => setTimeout(r, 0));
    });

    // First item: source matches accountId → sent
    expect(result.current.transactions[0].direction).toBe("sent");
    // Second item: source doesn't match → received
    expect(result.current.transactions[1].direction).toBe("received");
  });

  it("passes asset filter to fetchTransactions", async () => {
    mockedFetchTransactions.mockResolvedValueOnce({
      items: [mockItems[0]],
      nextCursor: undefined,
    });

    await renderHook(() => useTransactions(ACCOUNT_ID, { asset: "XLM" }));

    await act(async () => {
      await new Promise((r) => setTimeout(r, 0));
    });

    expect(mockedFetchTransactions).toHaveBeenCalledWith(ACCOUNT_ID, {
      cursor: undefined,
      asset: "XLM",
    });
  });

  it("saves first page to cache on successful fetch", async () => {
    mockedFetchTransactions.mockResolvedValueOnce({
      items: mockItems,
      nextCursor: "99-1-0",
    });

    const { result } = await renderHook(() => useTransactions(ACCOUNT_ID));

    await act(async () => {
      await new Promise((r) => setTimeout(r, 0));
    });

    expect(mockedSaveCache).toHaveBeenCalledWith(ACCOUNT_ID, {
      items: mockItems,
      nextCursor: "99-1-0",
    });
  });

  it("loadMore appends items and updates cursor", async () => {
    // First page
    mockedFetchTransactions.mockResolvedValueOnce({
      items: mockItems,
      nextCursor: "99-1-0",
    });

    const { result } = await renderHook(() => useTransactions(ACCOUNT_ID));

    await act(async () => {
      await new Promise((r) => setTimeout(r, 0));
    });

    expect(result.current.transactions).toHaveLength(2);

    // Second page
    const page2Items = [
      {
        amount: "10.0000000",
        asset: "XLM",
        timestamp: "2026-05-31T08:00:00Z",
        source: OTHER_ACCOUNT,
        destination: ACCOUNT_ID,
        status: "Success" as const,
        txHash: "ghi789",
        pagingToken: "98-1-0",
      },
    ];
    mockedFetchTransactions.mockResolvedValueOnce({
      items: page2Items,
      nextCursor: undefined,
    });

    await act(async () => {
      result.current.loadMore();
      await new Promise((r) => setTimeout(r, 0));
    });

    expect(result.current.transactions).toHaveLength(3);
    expect(result.current.hasMore).toBe(false);
    // loadMore should NOT save to cache (only first page does)
    expect(mockedSaveCache).toHaveBeenCalledTimes(1);
  });

  it("refresh resets data and fetches from the beginning", async () => {
    // Initial load
    mockedFetchTransactions.mockResolvedValueOnce({
      items: mockItems,
      nextCursor: "99-1-0",
    });

    const { result } = await renderHook(() => useTransactions(ACCOUNT_ID));

    await act(async () => {
      await new Promise((r) => setTimeout(r, 0));
    });

    // Refresh
    const freshItems = [
      {
        ...mockItems[0],
        amount: "100.0000000",
      },
    ];
    mockedFetchTransactions.mockResolvedValueOnce({
      items: freshItems,
      nextCursor: undefined,
    });

    await act(async () => {
      result.current.refresh();
      await new Promise((r) => setTimeout(r, 0));
    });

    expect(result.current.transactions).toHaveLength(1);
    expect(result.current.transactions[0].amount).toBe("100.0000000");
    expect(result.current.refreshing).toBe(false);
  });

  it("falls back to cache when offline and sets staleCache=true", async () => {
    mockedNetInfoFetch.mockResolvedValue({ isConnected: false } as any);
    mockedGetCache.mockResolvedValueOnce({
      items: mockItems,
      nextCursor: "99-1-0",
    });

    const { result } = await renderHook(() => useTransactions(ACCOUNT_ID));

    await act(async () => {
      await new Promise((r) => setTimeout(r, 0));
    });

    expect(result.current.loading).toBe(false);
    expect(result.current.transactions).toHaveLength(2);
    expect(result.current.staleCache).toBe(true);
    expect(result.current.error).toBeNull();
  });

  it("shows offline error when no cache is available", async () => {
    mockedNetInfoFetch.mockResolvedValue({ isConnected: false } as any);
    mockedGetCache.mockResolvedValueOnce(null);

    const { result } = await renderHook(() => useTransactions(ACCOUNT_ID));

    await act(async () => {
      await new Promise((r) => setTimeout(r, 0));
    });

    expect(result.current.loading).toBe(false);
    expect(result.current.error).toContain("offline");
    expect(result.current.transactions).toHaveLength(0);
  });

  it("falls back to cache on fetch error and sets staleCache=true", async () => {
    mockedFetchTransactions.mockRejectedValueOnce(new Error("Server error"));
    mockedGetCache.mockResolvedValueOnce({
      items: mockItems,
      nextCursor: undefined,
    });

    const { result } = await renderHook(() => useTransactions(ACCOUNT_ID));

    await act(async () => {
      await new Promise((r) => setTimeout(r, 0));
    });

    expect(result.current.transactions).toHaveLength(2);
    expect(result.current.staleCache).toBe(true);
    expect(result.current.error).toBeNull();
  });

  it("shows error when fetch fails and no cache available", async () => {
    mockedFetchTransactions.mockRejectedValueOnce(new Error("Server error"));
    mockedGetCache.mockResolvedValueOnce(null);

    const { result } = await renderHook(() => useTransactions(ACCOUNT_ID));

    await act(async () => {
      await new Promise((r) => setTimeout(r, 0));
    });

    expect(result.current.loading).toBe(false);
    expect(result.current.error).toBe("Server error");
    expect(result.current.transactions).toHaveLength(0);
    expect(result.current.staleCache).toBe(false);
  });

  it("does not fetch when already fetching (dedup)", async () => {
    mockedFetchTransactions.mockImplementation(
      () =>
        new Promise((resolve) =>
          setTimeout(
            () => resolve({ items: mockItems, nextCursor: undefined }),
            100,
          ),
        ),
    );

    const { result } = await renderHook(() => useTransactions(ACCOUNT_ID));

    // Try to trigger another load while first is in-flight
    await act(async () => {
      result.current.loadMore();
      await new Promise((r) => setTimeout(r, 10));
    });

    // Should only have called fetch once (the initial load)
    expect(mockedFetchTransactions).toHaveBeenCalledTimes(1);
  });

  it("handles empty transaction list", async () => {
    mockedFetchTransactions.mockResolvedValueOnce({
      items: [],
      nextCursor: undefined,
    });

    const { result } = await renderHook(() => useTransactions(ACCOUNT_ID));

    await act(async () => {
      await new Promise((r) => setTimeout(r, 0));
    });

    expect(result.current.transactions).toHaveLength(0);
    expect(result.current.hasMore).toBe(false);
    expect(result.current.loading).toBe(false);
  });
});
