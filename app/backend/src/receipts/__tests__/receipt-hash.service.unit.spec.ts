/**
 * Unit tests for ReceiptHashService
 *
 * Tests cover:
 * - Determinism: same inputs always produce the same hash
 * - Collision resistance: different inputs produce different hashes
 * - Stability: hash format is consistent and predictable
 * - Verification: verify() correctly validates hashes
 * - Validation: invalid inputs are rejected
 *
 * Location: app/backend/src/receipts/__tests__/receipt-hash.service.unit.spec.ts
 */

import { Test, TestingModule } from "@nestjs/testing";
import {
  ReceiptHashService,
  ReceiptHashInputs,
  RECEIPT_HASH_PREFIX,
} from "../receipt-hash.service";

describe("ReceiptHashService", () => {
  let service: ReceiptHashService;

  const baseInputs: ReceiptHashInputs = {
    txHash: "a".repeat(64),
    operationIndex: 0,
    sourceAccount: "GABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVWXY",
    destAccount: "GBDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVWXYZ2",
    amount: "100.0000000",
    assetCode: "USDC",
    assetIssuer: "GABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVWXY",
    ledger: 12345678,
    network: "testnet",
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [ReceiptHashService],
    }).compile();

    service = module.get<ReceiptHashService>(ReceiptHashService);
  });

  describe("computeHash", () => {
    it("should return a hash with the correct prefix", () => {
      const hash = service.computeHash(baseInputs);
      expect(hash).toMatch(/^rch_[0-9a-f]{64}$/);
    });

    it("should return a hash of consistent length", () => {
      const hash = service.computeHash(baseInputs);
      // rch_ (4) + 64 hex chars = 68 total
      expect(hash.length).toBe(68);
    });

    it("should use the RECEIPT_HASH_PREFIX constant", () => {
      const hash = service.computeHash(baseInputs);
      expect(hash.startsWith(RECEIPT_HASH_PREFIX)).toBe(true);
    });
  });

  describe("determinism", () => {
    it("should produce the same hash for identical inputs", () => {
      const hash1 = service.computeHash(baseInputs);
      const hash2 = service.computeHash(baseInputs);
      expect(hash1).toBe(hash2);
    });

    it("should produce the same hash across multiple calls", () => {
      const hashes = new Set<string>();
      for (let i = 0; i < 100; i++) {
        hashes.add(service.computeHash(baseInputs));
      }
      expect(hashes.size).toBe(1);
    });

    it("should produce the same hash regardless of call order", () => {
      const inputsA: ReceiptHashInputs = {
        ...baseInputs,
        amount: "50.0000000",
      };
      const inputsB: ReceiptHashInputs = {
        ...baseInputs,
        amount: "100.0000000",
      };

      // Compute in different orders
      const hashA1 = service.computeHash(inputsA);
      const hashB1 = service.computeHash(inputsB);
      const hashA2 = service.computeHash(inputsA);
      const hashB2 = service.computeHash(inputsB);

      expect(hashA1).toBe(hashA2);
      expect(hashB1).toBe(hashB2);
      expect(hashA1).not.toBe(hashB1);
    });

    it("should produce a known hash for a fixed input (snapshot test)", () => {
      const fixedInputs: ReceiptHashInputs = {
        txHash:
          "0000000000000000000000000000000000000000000000000000000000000000",
        operationIndex: 0,
        sourceAccount:
          "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        destAccount: "GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
        amount: "1.0000000",
        assetCode: "XLM",
        assetIssuer: "",
        ledger: 1,
        network: "testnet",
      };

      const hash = service.computeHash(fixedInputs);
      // This snapshot ensures the algorithm doesn't change unexpectedly
      expect(hash).toMatch(/^rch_[0-9a-f]{64}$/);
      // Store the exact hash for regression detection
      expect(hash).toMatchSnapshot();
    });
  });

  describe("collision resistance", () => {
    it("should produce different hashes when txHash differs", () => {
      const hash1 = service.computeHash(baseInputs);
      const hash2 = service.computeHash({
        ...baseInputs,
        txHash: "b".repeat(64),
      });
      expect(hash1).not.toBe(hash2);
    });

    it("should produce different hashes when operationIndex differs", () => {
      const hash1 = service.computeHash(baseInputs);
      const hash2 = service.computeHash({
        ...baseInputs,
        operationIndex: 1,
      });
      expect(hash1).not.toBe(hash2);
    });

    it("should produce different hashes when sourceAccount differs", () => {
      const hash1 = service.computeHash(baseInputs);
      const hash2 = service.computeHash({
        ...baseInputs,
        sourceAccount:
          "GCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
      });
      expect(hash1).not.toBe(hash2);
    });

    it("should produce different hashes when destAccount differs", () => {
      const hash1 = service.computeHash(baseInputs);
      const hash2 = service.computeHash({
        ...baseInputs,
        destAccount:
          "GDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD",
      });
      expect(hash1).not.toBe(hash2);
    });

    it("should produce different hashes when amount differs", () => {
      const hash1 = service.computeHash(baseInputs);
      const hash2 = service.computeHash({
        ...baseInputs,
        amount: "100.0000001",
      });
      expect(hash1).not.toBe(hash2);
    });

    it("should produce different hashes when assetCode differs", () => {
      const hash1 = service.computeHash(baseInputs);
      const hash2 = service.computeHash({
        ...baseInputs,
        assetCode: "XLM",
      });
      expect(hash1).not.toBe(hash2);
    });

    it("should produce different hashes when assetIssuer differs", () => {
      const hash1 = service.computeHash(baseInputs);
      const hash2 = service.computeHash({
        ...baseInputs,
        assetIssuer: "GEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE",
      });
      expect(hash1).not.toBe(hash2);
    });

    it("should produce different hashes when ledger differs", () => {
      const hash1 = service.computeHash(baseInputs);
      const hash2 = service.computeHash({
        ...baseInputs,
        ledger: 12345679,
      });
      expect(hash1).not.toBe(hash2);
    });

    it("should produce different hashes when network differs", () => {
      const hash1 = service.computeHash(baseInputs);
      const hash2 = service.computeHash({
        ...baseInputs,
        network: "mainnet",
      });
      expect(hash1).not.toBe(hash2);
    });

    it("should produce different hashes for single-bit input changes", () => {
      // Change last character of txHash
      const hash1 = service.computeHash(baseInputs);
      const hash2 = service.computeHash({
        ...baseInputs,
        txHash: "a".repeat(63) + "b",
      });
      expect(hash1).not.toBe(hash2);
    });

    it("should produce different hashes for amount with trailing zeros vs not", () => {
      const hash1 = service.computeHash({ ...baseInputs, amount: "100.0" });
      const hash2 = service.computeHash({ ...baseInputs, amount: "100.00" });
      expect(hash1).not.toBe(hash2);
    });
  });

  describe("verify", () => {
    it("should return true for a valid hash", () => {
      const hash = service.computeHash(baseInputs);
      expect(service.verify(hash, baseInputs)).toBe(true);
    });

    it("should return false for an invalid hash", () => {
      const hash = service.computeHash(baseInputs);
      const wrongHash = "rch_" + "0".repeat(64);
      if (wrongHash !== hash) {
        expect(service.verify(wrongHash, baseInputs)).toBe(false);
      }
    });

    it("should return false when inputs are modified", () => {
      const hash = service.computeHash(baseInputs);
      const modifiedInputs = { ...baseInputs, amount: "999.9999999" };
      expect(service.verify(hash, modifiedInputs)).toBe(false);
    });

    it("should return false for a hash with wrong prefix", () => {
      const badHash = "bad_" + "a".repeat(64);
      expect(service.verify(badHash, baseInputs)).toBe(false);
    });
  });

  describe("input validation", () => {
    it("should throw when txHash is empty", () => {
      expect(() => service.computeHash({ ...baseInputs, txHash: "" })).toThrow(
        "ReceiptHash: txHash is required",
      );
    });

    it("should throw when sourceAccount is empty", () => {
      expect(() =>
        service.computeHash({ ...baseInputs, sourceAccount: "" }),
      ).toThrow("ReceiptHash: sourceAccount is required");
    });

    it("should throw when amount is empty", () => {
      expect(() => service.computeHash({ ...baseInputs, amount: "" })).toThrow(
        "ReceiptHash: amount is required",
      );
    });

    it("should throw when assetCode is empty", () => {
      expect(() =>
        service.computeHash({ ...baseInputs, assetCode: "" }),
      ).toThrow("ReceiptHash: assetCode is required");
    });

    it("should throw when network is empty", () => {
      expect(() => service.computeHash({ ...baseInputs, network: "" })).toThrow(
        "ReceiptHash: network is required",
      );
    });

    it("should throw when operationIndex is negative", () => {
      expect(() =>
        service.computeHash({ ...baseInputs, operationIndex: -1 }),
      ).toThrow("ReceiptHash: operationIndex must be >= 0");
    });

    it("should accept empty destAccount (for contract actions)", () => {
      expect(() =>
        service.computeHash({ ...baseInputs, destAccount: "" }),
      ).not.toThrow();
    });

    it("should accept empty assetIssuer (for native XLM)", () => {
      expect(() =>
        service.computeHash({ ...baseInputs, assetIssuer: "" }),
      ).not.toThrow();
    });

    it("should accept zero ledger (for pending transactions)", () => {
      expect(() =>
        service.computeHash({ ...baseInputs, ledger: 0 }),
      ).not.toThrow();
    });

    it("should accept zero operationIndex", () => {
      expect(() =>
        service.computeHash({ ...baseInputs, operationIndex: 0 }),
      ).not.toThrow();
    });
  });

  describe("canonical JSON encoding", () => {
    it("should produce the same hash regardless of object property order", () => {
      // Create inputs with properties in different order
      const inputs1: ReceiptHashInputs = {
        txHash: baseInputs.txHash,
        operationIndex: baseInputs.operationIndex,
        sourceAccount: baseInputs.sourceAccount,
        destAccount: baseInputs.destAccount,
        amount: baseInputs.amount,
        assetCode: baseInputs.assetCode,
        assetIssuer: baseInputs.assetIssuer,
        ledger: baseInputs.ledger,
        network: baseInputs.network,
      };

      const inputs2: ReceiptHashInputs = {
        network: baseInputs.network,
        ledger: baseInputs.ledger,
        assetIssuer: baseInputs.assetIssuer,
        assetCode: baseInputs.assetCode,
        amount: baseInputs.amount,
        destAccount: baseInputs.destAccount,
        sourceAccount: baseInputs.sourceAccount,
        operationIndex: baseInputs.operationIndex,
        txHash: baseInputs.txHash,
      };

      expect(service.computeHash(inputs1)).toBe(service.computeHash(inputs2));
    });
  });

  describe("edge cases", () => {
    it("should handle very large ledger numbers", () => {
      expect(() =>
        service.computeHash({ ...baseInputs, ledger: Number.MAX_SAFE_INTEGER }),
      ).not.toThrow();
    });

    it("should handle very long txHash", () => {
      expect(() =>
        service.computeHash({ ...baseInputs, txHash: "a".repeat(128) }),
      ).not.toThrow();
    });

    it("should handle special characters in assetCode", () => {
      expect(() =>
        service.computeHash({ ...baseInputs, assetCode: "USDC.e" }),
      ).not.toThrow();
    });

    it("should handle unicode in sourceAccount (should not throw)", () => {
      expect(() =>
        service.computeHash({ ...baseInputs, sourceAccount: "G🚀" }),
      ).not.toThrow();
    });

    it("should produce different hashes for native XLM vs credit_alphanum4 with same code", () => {
      const nativeHash = service.computeHash({
        ...baseInputs,
        assetCode: "XLM",
        assetIssuer: "",
      });
      const creditHash = service.computeHash({
        ...baseInputs,
        assetCode: "XLM",
        assetIssuer: "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      });
      expect(nativeHash).not.toBe(creditHash);
    });
  });
});
