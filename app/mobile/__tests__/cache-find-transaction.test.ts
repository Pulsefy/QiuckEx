/**
 * Unit tests for findTransactionInCache.
 * We mock AsyncStorage to avoid side effects.
 */

import AsyncStorage from "@react-native-async-storage/async-storage";
import { findTransactionInCache } from "../services/cache";

jest.mock("@react-native-async-storage/async-storage", () => ({
    getAllKeys: jest.fn(),
    getItem: jest.fn(),
}));

const mockedGetAllKeys = AsyncStorage.getAllKeys as jest.Mock;
const mockedGetItem = AsyncStorage.getItem as jest.Mock;

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
});
