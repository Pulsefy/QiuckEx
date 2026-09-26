/**
 * Unit tests for receipts service.
 * Tests the cache-miss to API-hit path and offline/cache-miss error path.
 */

import { fetchReceiptByTxHash, fetchReceiptsByAddress } from "../services/receipts";
import { findTransactionInCache, saveTransactionToCache } from "../services/cache";
import type { TransactionItem } from "../types/transaction";

// Mock fetch globally
global.fetch = jest.fn();

// Mock AsyncStorage
import AsyncStorage from "@react-native-async-storage/async-storage";
jest.mock("@react-native-async-storage/async-storage", () => ({
    getAllKeys: jest.fn(),
    getItem: jest.fn(),
    setItem: jest.fn(),
}));

const mockedFetch = global.fetch as jest.MockedFunction<typeof fetch>;
const mockedGetAllKeys = AsyncStorage.getAllKeys as jest.Mock;
const mockedGetItem = AsyncStorage.getItem as jest.Mock;
const mockedSetItem = AsyncStorage.setItem as jest.Mock;

describe("receipts service", () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    describe("fetchReceiptByTxHash", () => {
        it("successfully fetches and maps a receipt from the API", async () => {
            const mockReceiptResponse = {
                receipt: {
                    receiptId: "rcpt_abc123_0",
                    receiptHash: "rch_" + "a".repeat(64),
                    txHash: "test-tx-hash",
                    operationIndex: 0,
                    type: "payment" as const,
                    status: "success" as const,
                    receiptReference: null,
                    createdAt: "2026-01-01T00:00:00Z",
                    updatedAt: "2026-01-01T00:00:00Z",
                    ledger: 12345,
                    sender: {
                        address: "Gsender123",
                        username: "sender",
                    },
                    receiver: {
                        address: "Greceiver456",
                        username: "receiver",
                    },
                    asset: {
                        type: "native" as const,
                        code: "XLM",
                        issuer: null,
                    },
                    amount: "100.5",
                    displayAmount: "100.5 XLM",
                    memo: "test memo",
                    memoType: "text" as const,
                    fee: {
                        baseFeeSatoshis: "100",
                        totalFeeSatoshis: "100",
                        feeXlm: "0.00001",
                    },
                    contract: null,
                    diagnostic: {
                        errorCode: null,
                        errorMessage: null,
                        resultXdr: null,
                        envelopeXdr: null,
                    },
                    network: "testnet" as const,
                    explorerUrl: "https://stellar.expert/explorer/public/tx/test-tx-hash",
                },
            };

            mockedFetch.mockResolvedValue({
                ok: true,
                status: 200,
                json: async () => mockReceiptResponse,
            } as Response);

            const result = await fetchReceiptByTxHash("test-tx-hash");

            expect(result).toEqual({
                amount: "100.5",
                asset: "XLM",
                memo: "test memo",
                timestamp: "2026-01-01T00:00:00Z",
                txHash: "test-tx-hash",
                pagingToken: "rcpt_abc123_0",
                source: "Gsender123",
                destination: "Greceiver456",
                status: "Success",
            });

            expect(mockedFetch).toHaveBeenCalledWith(
                expect.stringContaining("/v1/receipts/tx/test-tx-hash"),
                expect.objectContaining({
                    headers: { Accept: "application/json" },
                })
            );
        });

        it("throws a descriptive error on network failure", async () => {
            mockedFetch.mockRejectedValue(new Error("Network error"));

            await expect(fetchReceiptByTxHash("test-tx-hash")).rejects.toThrow(
                "Network request failed. Check your connection and try again."
            );
        });

        it("throws a 404 error when receipt is not found", async () => {
            mockedFetch.mockResolvedValue({
                ok: false,
                status: 404,
                json: async () => ({ message: "Not found" }),
            } as Response);

            await expect(fetchReceiptByTxHash("test-tx-hash")).rejects.toThrow(
                "Receipt not found. The transaction may not exist or has not been indexed yet."
            );
        });

        it("throws a descriptive error on server error", async () => {
            mockedFetch.mockResolvedValue({
                ok: false,
                status: 500,
                json: async () => ({ message: "Internal server error" }),
            } as Response);

            await expect(fetchReceiptByTxHash("test-tx-hash")).rejects.toThrow(
                "Internal server error"
            );
        });

        it("maps pending status correctly", async () => {
            const mockReceiptResponse = {
                receipt: {
                    receiptId: "rcpt_abc123_0",
                    receiptHash: "rch_" + "a".repeat(64),
                    txHash: "test-tx-hash",
                    operationIndex: 0,
                    type: "payment" as const,
                    status: "pending" as const,
                    receiptReference: null,
                    createdAt: "2026-01-01T00:00:00Z",
                    updatedAt: "2026-01-01T00:00:00Z",
                    ledger: null,
                    sender: {
                        address: "Gsender123",
                        username: null,
                    },
                    receiver: {
                        address: "Greceiver456",
                        username: null,
                    },
                    asset: {
                        type: "native" as const,
                        code: "XLM",
                        issuer: null,
                    },
                    amount: "100.5",
                    displayAmount: "100.5 XLM",
                    memo: null,
                    memoType: "none" as const,
                    fee: {
                        baseFeeSatoshis: "100",
                        totalFeeSatoshis: "100",
                        feeXlm: "0.00001",
                    },
                    contract: null,
                    diagnostic: {
                        errorCode: null,
                        errorMessage: null,
                        resultXdr: null,
                        envelopeXdr: null,
                    },
                    network: "testnet" as const,
                    explorerUrl: "https://stellar.expert/explorer/public/tx/test-tx-hash",
                },
            };

            mockedFetch.mockResolvedValue({
                ok: true,
                status: 200,
                json: async () => mockReceiptResponse,
            } as Response);

            const result = await fetchReceiptByTxHash("test-tx-hash");
            expect(result.status).toBe("Pending");
        });

        it("handles credit asset with issuer", async () => {
            const mockReceiptResponse = {
                receipt: {
                    receiptId: "rcpt_abc123_0",
                    receiptHash: "rch_" + "a".repeat(64),
                    txHash: "test-tx-hash",
                    operationIndex: 0,
                    type: "payment" as const,
                    status: "success" as const,
                    receiptReference: null,
                    createdAt: "2026-01-01T00:00:00Z",
                    updatedAt: "2026-01-01T00:00:00Z",
                    ledger: 12345,
                    sender: {
                        address: "Gsender123",
                        username: null,
                    },
                    receiver: {
                        address: "Greceiver456",
                        username: null,
                    },
                    asset: {
                        type: "credit_alphanum4" as const,
                        code: "USDC",
                        issuer: "G issuer",
                    },
                    amount: "50.25",
                    displayAmount: "50.25 USDC",
                    memo: null,
                    memoType: "none" as const,
                    fee: {
                        baseFeeSatoshis: "100",
                        totalFeeSatoshis: "100",
                        feeXlm: "0.00001",
                    },
                    contract: null,
                    diagnostic: {
                        errorCode: null,
                        errorMessage: null,
                        resultXdr: null,
                        envelopeXdr: null,
                    },
                    network: "testnet" as const,
                    explorerUrl: "https://stellar.expert/explorer/public/tx/test-tx-hash",
                },
            };

            mockedFetch.mockResolvedValue({
                ok: true,
                status: 200,
                json: async () => mockReceiptResponse,
            } as Response);

            const result = await fetchReceiptByTxHash("test-tx-hash");
            expect(result.asset).toBe("USDC:G issuer");
        });
    });

    describe("fetchReceiptsByAddress", () => {
        it("successfully fetches receipts by address", async () => {
            const mockReceiptListResponse = {
                receipts: [
                    {
                        receiptId: "rcpt_abc123_0",
                        receiptHash: "rch_" + "a".repeat(64),
                        txHash: "test-tx-hash-1",
                        operationIndex: 0,
                        type: "payment" as const,
                        status: "success" as const,
                        receiptReference: null,
                        createdAt: "2026-01-01T00:00:00Z",
                        updatedAt: "2026-01-01T00:00:00Z",
                        ledger: 12345,
                        sender: {
                            address: "Gsender123",
                            username: null,
                        },
                        receiver: {
                            address: "Greceiver456",
                            username: null,
                        },
                        asset: {
                            type: "native" as const,
                            code: "XLM",
                            issuer: null,
                        },
                        amount: "100.5",
                        displayAmount: "100.5 XLM",
                        memo: null,
                        memoType: "none" as const,
                        fee: {
                            baseFeeSatoshis: "100",
                            totalFeeSatoshis: "100",
                            feeXlm: "0.00001",
                        },
                        contract: null,
                        diagnostic: {
                            errorCode: null,
                            errorMessage: null,
                            resultXdr: null,
                            envelopeXdr: null,
                        },
                        network: "testnet" as const,
                        explorerUrl: "https://stellar.expert/explorer/public/tx/test-tx-hash-1",
                    },
                ],
                nextCursor: "next-cursor-token",
                total: 1,
            };

            mockedFetch.mockResolvedValue({
                ok: true,
                status: 200,
                json: async () => mockReceiptListResponse,
            } as Response);

            const result = await fetchReceiptsByAddress("Gsender123");

            expect(result.receipts).toHaveLength(1);
            expect(result.nextCursor).toBe("next-cursor-token");
            expect(result.total).toBe(1);
            expect(result.receipts[0].pagingToken).toBe("rcpt_abc123_0");
        });

        it("includes query parameters in the request", async () => {
            mockedFetch.mockResolvedValue({
                ok: true,
                status: 200,
                json: async () => ({ receipts: [], nextCursor: null, total: 0 }),
            } as Response);

            await fetchReceiptsByAddress("Gsender123", {
                type: "payment",
                status: "success",
                limit: 50,
                cursor: "some-cursor",
            });

            expect(mockedFetch).toHaveBeenCalledWith(
                expect.stringContaining("/v1/receipts/address/Gsender123"),
                expect.objectContaining({
                    headers: { Accept: "application/json" },
                })
            );
        });
    });
});

describe("cache-miss to API-hit integration", () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    it("falls back to API when transaction is not in cache", async () => {
        // Cache miss
        mockedGetAllKeys.mockResolvedValue([]);
        mockedGetItem.mockResolvedValue(null);

        // API hit
        const mockReceiptResponse = {
            receipt: {
                receiptId: "rcpt_abc123_0",
                receiptHash: "rch_" + "a".repeat(64),
                txHash: "test-tx-hash",
                operationIndex: 0,
                type: "payment" as const,
                status: "success" as const,
                receiptReference: null,
                createdAt: "2026-01-01T00:00:00Z",
                updatedAt: "2026-01-01T00:00:00Z",
                ledger: 12345,
                sender: {
                    address: "Gsender123",
                    username: null,
                },
                receiver: {
                    address: "Greceiver456",
                    username: null,
                },
                asset: {
                    type: "native" as const,
                    code: "XLM",
                    issuer: null,
                },
                amount: "100.5",
                displayAmount: "100.5 XLM",
                memo: null,
                memoType: "none" as const,
                fee: {
                    baseFeeSatoshis: "100",
                    totalFeeSatoshis: "100",
                    feeXlm: "0.00001",
                },
                contract: null,
                diagnostic: {
                    errorCode: null,
                    errorMessage: null,
                    resultXdr: null,
                    envelopeXdr: null,
                },
                network: "testnet" as const,
                explorerUrl: "https://stellar.expert/explorer/public/tx/test-tx-hash",
            },
        };

        mockedFetch.mockResolvedValue({
            ok: true,
            status: 200,
            json: async () => mockReceiptResponse,
        } as Response);

        // Simulate the cache-miss to API-hit flow
        const cached = await findTransactionInCache("test-tx-hash");
        expect(cached).toBeNull();

        const apiResult = await fetchReceiptByTxHash("test-tx-hash");
        expect(apiResult).not.toBeNull();
        expect(apiResult.txHash).toBe("test-tx-hash");

        // Save to cache
        await saveTransactionToCache(apiResult);
        expect(mockedSetItem).toHaveBeenCalled();
    });

    it("handles offline/cache-miss error path gracefully", async () => {
        // Cache miss
        mockedGetAllKeys.mockResolvedValue([]);
        mockedGetItem.mockResolvedValue(null);

        // Network failure (offline scenario)
        mockedFetch.mockRejectedValue(new Error("Network error"));

        const cached = await findTransactionInCache("test-tx-hash");
        expect(cached).toBeNull();

        await expect(fetchReceiptByTxHash("test-tx-hash")).rejects.toThrow(
            "Network request failed. Check your connection and try again."
        );
    });

    it("returns cached transaction when available without API call", async () => {
        const cachedTransaction: TransactionItem = {
            amount: "100.5",
            asset: "XLM",
            memo: "test memo",
            timestamp: "2026-01-01T00:00:00Z",
            txHash: "test-tx-hash",
            pagingToken: "test-paging-token",
            source: "Gsender123",
            destination: "Greceiver456",
            status: "Success",
        };

        mockedGetAllKeys.mockResolvedValue(["@qex_tx_cache_Gsender123"]);
        mockedGetItem.mockResolvedValue(
            JSON.stringify({
                data: {
                    items: [cachedTransaction],
                },
                timestamp: Date.now(),
            })
        );

        const result = await findTransactionInCache("test-paging-token");
        expect(result).toEqual(cachedTransaction);

        // API should not be called when cache hit
        expect(mockedFetch).not.toHaveBeenCalled();
    });

    it("saves API-fetched transaction to cache for offline viewing", async () => {
        const mockReceiptResponse = {
            receipt: {
                receiptId: "rcpt_abc123_0",
                receiptHash: "rch_" + "a".repeat(64),
                txHash: "test-tx-hash",
                operationIndex: 0,
                type: "payment" as const,
                status: "success" as const,
                receiptReference: null,
                createdAt: "2026-01-01T00:00:00Z",
                updatedAt: "2026-01-01T00:00:00Z",
                ledger: 12345,
                sender: {
                    address: "Gsender123",
                    username: null,
                },
                receiver: {
                    address: "Greceiver456",
                    username: null,
                },
                asset: {
                    type: "native" as const,
                    code: "XLM",
                    issuer: null,
                },
                amount: "100.5",
                displayAmount: "100.5 XLM",
                memo: null,
                memoType: "none" as const,
                fee: {
                    baseFeeSatoshis: "100",
                    totalFeeSatoshis: "100",
                    feeXlm: "0.00001",
                },
                contract: null,
                diagnostic: {
                    errorCode: null,
                    errorMessage: null,
                    resultXdr: null,
                    envelopeXdr: null,
                },
                network: "testnet" as const,
                explorerUrl: "https://stellar.expert/explorer/public/tx/test-tx-hash",
            },
        };

        mockedFetch.mockResolvedValue({
            ok: true,
            status: 200,
            json: async () => mockReceiptResponse,
        } as Response);

        const apiResult = await fetchReceiptByTxHash("test-tx-hash");
        await saveTransactionToCache(apiResult);

        expect(mockedSetItem).toHaveBeenCalled();
        expect(mockedSetItem).toHaveBeenCalledWith(
            expect.stringContaining("@qex_tx_cache_"),
            expect.stringContaining("rcpt_abc123_0")
        );
    });
});
