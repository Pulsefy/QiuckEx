/**
 * Unit tests for findTransactionInCache and saveTransactionToCache.
 * We mock AsyncStorage to avoid side effects.
 */

import AsyncStorage from "@react-native-async-storage/async-storage";
import { findTransactionInCache, saveTransactionToCache } from "../services/cache";
import type { TransactionItem } from "../types/transaction";

jest.mock("@react-native-async-storage/async-storage", () => ({
    getAllKeys: jest.fn(),
    getItem: jest.fn(),
    setItem: jest.fn(),
}));

const mockedGetAllKeys = AsyncStorage.getAllKeys as jest.Mock;
const mockedGetItem = AsyncStorage.getItem as jest.Mock;
const mockedSetItem = AsyncStorage.setItem as jest.Mock;

describe("findTransactionInCache", () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    it("returns the matching transaction from a single cached account", async () => {
        mockedGetAllKeys.mockResolvedValue(["@qex_tx_cache_GABC"]);
        mockedGetItem.mockResolvedValue(
            JSON.stringify({
                data: {
                    items: [
                        {
                            pagingToken: "token-1",
                            amount: "10",
                            asset: "XLM",
                            timestamp: "2026-01-01T00:00:00Z",
                            txHash: "hash1",
                            source: "G1",
                            destination: "G2",
                            status: "Success",
                        },
                        {
                            pagingToken: "token-2",
                            amount: "20",
                            asset: "USDC",
                            timestamp: "2026-01-02T00:00:00Z",
                            txHash: "hash2",
                            source: "G3",
                            destination: "G4",
                            status: "Pending",
                        },
                    ],
                    nextCursor: "cursor",
                },
                timestamp: Date.now(),
            }),
        );

        const result = await findTransactionInCache("token-2");
        expect(result).not.toBeNull();
        expect(result!.pagingToken).toBe("token-2");
        expect(result!.amount).toBe("20");
    });

    it("returns null when no cache keys exist", async () => {
        mockedGetAllKeys.mockResolvedValue([]);

        const result = await findTransactionInCache("token-x");
        expect(result).toBeNull();
    });

    it("returns null when transaction is not found in any cache", async () => {
        mockedGetAllKeys.mockResolvedValue(["@qex_tx_cache_GABC"]);
        mockedGetItem.mockResolvedValue(
            JSON.stringify({
                data: {
                    items: [
                        {
                            pagingToken: "token-1",
                            amount: "10",
                            asset: "XLM",
                            timestamp: "2026-01-01T00:00:00Z",
                            txHash: "hash1",
                            source: "G1",
                            destination: "G2",
                            status: "Success",
                        },
                    ],
                    nextCursor: undefined,
                },
                timestamp: Date.now(),
            }),
        );

        const result = await findTransactionInCache("missing");
        expect(result).toBeNull();
    });

    it("gracefully handles JSON parse errors", async () => {
        mockedGetAllKeys.mockResolvedValue(["@qex_tx_cache_GABC"]);
        mockedGetItem.mockResolvedValue("invalid-json");

        const result = await findTransactionInCache("token-1");
        expect(result).toBeNull();
    });

    it("returns transaction from standalone individual cache entry", async () => {
        mockedGetAllKeys.mockResolvedValue(["@qex_tx_cache_individual_token-standalone"]);
        mockedGetItem.mockResolvedValue(
            JSON.stringify({
                data: {
                    items: [
                        {
                            pagingToken: "token-standalone",
                            amount: "50",
                            asset: "XLM",
                            timestamp: "2026-01-01T00:00:00Z",
                            txHash: "hash-standalone",
                            source: "Gsender",
                            destination: "Greceiver",
                            status: "Success",
                        },
                    ],
                },
                timestamp: Date.now(),
            }),
        );

        const result = await findTransactionInCache("token-standalone");
        expect(result).not.toBeNull();
        expect(result!.pagingToken).toBe("token-standalone");
        expect(result!.amount).toBe("50");
    });
});

describe("saveTransactionToCache", () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    it("saves a standalone transaction when no matching account cache exists", async () => {
        const transaction = {
            pagingToken: "token-new",
            amount: "100",
            asset: "XLM",
            timestamp: "2026-01-01T00:00:00Z",
            txHash: "hash-new",
            source: "Gsender",
            destination: "Greceiver",
            status: "Success" as const,
        };

        mockedGetAllKeys.mockResolvedValue([]);
        mockedSetItem.mockResolvedValue(undefined);

        await saveTransactionToCache(transaction);

        expect(mockedSetItem).toHaveBeenCalledWith(
            "@qex_tx_cache_individual_token-new",
            expect.stringContaining("token-new")
        );
    });

    it("updates existing transaction in account cache", async () => {
        const transaction = {
            pagingToken: "token-1",
            amount: "999", // Updated amount
            asset: "XLM",
            timestamp: "2026-01-01T00:00:00Z",
            txHash: "hash1",
            source: "G1",
            destination: "G2",
            status: "Success" as const,
        };

        mockedGetAllKeys.mockResolvedValue(["@qex_tx_cache_G1"]);
        mockedGetItem.mockResolvedValue(
            JSON.stringify({
                data: {
                    items: [
                        {
                            pagingToken: "token-1",
                            amount: "10", // Old amount
                            asset: "XLM",
                            timestamp: "2026-01-01T00:00:00Z",
                            txHash: "hash1",
                            source: "G1",
                            destination: "G2",
                            status: "Success",
                        },
                    ],
                },
                timestamp: Date.now(),
            }),
        );
        mockedSetItem.mockResolvedValue(undefined);

        await saveTransactionToCache(transaction);

        expect(mockedSetItem).toHaveBeenCalled();
        const savedData = JSON.parse((mockedSetItem.mock.calls[0][1] as string));
        expect(savedData.data.items[0].amount).toBe("999");
    });

    it("adds transaction to account cache when source matches", async () => {
        const transaction = {
            pagingToken: "token-new",
            amount: "100",
            asset: "XLM",
            timestamp: "2026-01-01T00:00:00Z",
            txHash: "hash-new",
            source: "G1",
            destination: "G2",
            status: "Success" as const,
        };

        mockedGetAllKeys.mockResolvedValue(["@qex_tx_cache_G1"]);
        mockedGetItem.mockResolvedValue(
            JSON.stringify({
                data: {
                    items: [
                        {
                            pagingToken: "token-existing",
                            amount: "10",
                            asset: "XLM",
                            timestamp: "2026-01-01T00:00:00Z",
                            txHash: "hash-existing",
                            source: "G1",
                            destination: "Gother",
                            status: "Success",
                        },
                    ],
                },
                timestamp: Date.now(),
            }),
        );
        mockedSetItem.mockResolvedValue(undefined);

        await saveTransactionToCache(transaction);

        expect(mockedSetItem).toHaveBeenCalled();
        const savedData = JSON.parse((mockedSetItem.mock.calls[0][1] as string));
        expect(savedData.data.items).toHaveLength(2);
        expect(savedData.data.items[0].pagingToken).toBe("token-new");
    });

    it("adds transaction to account cache when destination matches", async () => {
        const transaction = {
            pagingToken: "token-new",
            amount: "100",
            asset: "XLM",
            timestamp: "2026-01-01T00:00:00Z",
            txHash: "hash-new",
            source: "Gsender",
            destination: "G1",
            status: "Success" as const,
        };

        mockedGetAllKeys.mockResolvedValue(["@qex_tx_cache_G1"]);
        mockedGetItem.mockResolvedValue(
            JSON.stringify({
                data: {
                    items: [],
                },
                timestamp: Date.now(),
            }),
        );
        mockedSetItem.mockResolvedValue(undefined);

        await saveTransactionToCache(transaction);

        expect(mockedSetItem).toHaveBeenCalled();
        const savedData = JSON.parse((mockedSetItem.mock.calls[0][1] as string));
        expect(savedData.data.items).toHaveLength(1);
        expect(savedData.data.items[0].pagingToken).toBe("token-new");
    });

    it("gracefully handles AsyncStorage errors", async () => {
        const transaction = {
            pagingToken: "token-new",
            amount: "100",
            asset: "XLM",
            timestamp: "2026-01-01T00:00:00Z",
            txHash: "hash-new",
            source: "Gsender",
            destination: "Greceiver",
            status: "Success" as const,
        };

        mockedGetAllKeys.mockRejectedValue(new Error("Storage error"));

        // Should not throw, just log error
        await expect(saveTransactionToCache(transaction)).resolves.not.toThrow();
    });
});
