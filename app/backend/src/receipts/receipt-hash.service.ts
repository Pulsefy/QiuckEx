/**
 * ReceiptHashService
 *
 * Generates a deterministic receipt hash from canonical transaction data.
 * The hash is stable across retries and can be used by off-chain receipts,
 * indexers, and support tooling to reference contract outcomes consistently.
 *
 * Canonical inputs (sorted, deterministic JSON → SHA-256):
 *   - txHash           Stellar transaction hash (64 hex chars)
 *   - operationIndex   Index of the operation within the transaction
 *   - sourceAccount    Sender Stellar public key
 *   - destAccount      Receiver Stellar public key (empty string if none)
 *   - amount           Exact amount string (no floating-point)
 *   - assetCode        Asset code (XLM, USDC, etc.)
 *   - assetIssuer      Asset issuer address (empty string for native XLM)
 *   - ledger           Ledger sequence number (0 if not yet closed)
 *   - network          Stellar network identifier (testnet | mainnet)
 *
 * Output format: `rch_<64 hex chars>`
 *
 * Location: app/backend/src/receipts/receipt-hash.service.ts
 */

import { Injectable, Logger } from "@nestjs/common";
import { createHash } from "crypto";

/**
 * Canonical inputs required for receipt hash derivation.
 * All fields must be present; use empty string / 0 for absent values.
 */
export interface ReceiptHashInputs {
  txHash: string;
  operationIndex: number;
  sourceAccount: string;
  destAccount: string;
  amount: string;
  assetCode: string;
  assetIssuer: string;
  ledger: number;
  network: string;
}

/** Prefix for the deterministic receipt hash */
export const RECEIPT_HASH_PREFIX = "rch_";

@Injectable()
export class ReceiptHashService {
  private readonly logger = new Logger(ReceiptHashService.name);

  /**
   * Compute a deterministic receipt hash from canonical inputs.
   *
   * The same set of inputs will always produce the same hash,
   * regardless of call order, timing, or retries.
   *
   * @param inputs Canonical transaction fields
   * @returns Receipt hash string in format `rch_<sha256_hex>`
   */
  computeHash(inputs: ReceiptHashInputs): string {
    this.validateInputs(inputs);

    // Build canonical JSON: keys in fixed order, no whitespace, no undefined
    const canonical = this.buildCanonicalJson(inputs);

    // SHA-256 hash
    const hex = createHash("sha256").update(canonical, "utf8").digest("hex");

    return `${RECEIPT_HASH_PREFIX}${hex}`;
  }

  /**
   * Verify that a given receipt hash matches the expected canonical inputs.
   * Useful for indexers and support tools to validate receipt integrity.
   *
   * @param expectedHash The hash to verify
   * @param inputs The canonical inputs to check against
   * @returns true if the hash matches
   */
  verify(expectedHash: string, inputs: ReceiptHashInputs): boolean {
    const computed = this.computeHash(inputs);
    return computed === expectedHash;
  }

  /**
   * Build a deterministic JSON string from canonical inputs.
   * Keys are in a fixed, documented order to guarantee byte-identical output.
   */
  private buildCanonicalJson(inputs: ReceiptHashInputs): string {
    // Explicit key ordering ensures deterministic encoding
    // regardless of object property order in different JS engines.
    return JSON.stringify({
      amount: inputs.amount,
      assetCode: inputs.assetCode,
      assetIssuer: inputs.assetIssuer,
      destAccount: inputs.destAccount,
      ledger: inputs.ledger,
      network: inputs.network,
      operationIndex: inputs.operationIndex,
      sourceAccount: inputs.sourceAccount,
      txHash: inputs.txHash,
    });
  }

  /**
   * Validate that all required inputs are present and well-formed.
   * Throws BadRequestException on invalid inputs.
   */
  private validateInputs(inputs: ReceiptHashInputs): void {
    if (!inputs.txHash || inputs.txHash.length === 0) {
      throw new Error("ReceiptHash: txHash is required");
    }
    if (inputs.operationIndex < 0) {
      throw new Error("ReceiptHash: operationIndex must be >= 0");
    }
    if (!inputs.sourceAccount || inputs.sourceAccount.length === 0) {
      throw new Error("ReceiptHash: sourceAccount is required");
    }
    if (!inputs.amount || inputs.amount.length === 0) {
      throw new Error("ReceiptHash: amount is required");
    }
    if (!inputs.assetCode || inputs.assetCode.length === 0) {
      throw new Error("ReceiptHash: assetCode is required");
    }
    if (!inputs.network || inputs.network.length === 0) {
      throw new Error("ReceiptHash: network is required");
    }
  }
}
