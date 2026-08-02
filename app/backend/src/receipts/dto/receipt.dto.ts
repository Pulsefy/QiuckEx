/**
 * DTOs for the receipt normalization API.
 *
 * Location: app/backend/src/receipts/dto/receipt.dto.ts
 */

import { IsString, IsIn, IsOptional, IsInt, Min } from "class-validator";
import { NormalizedReceipt } from "../schemas/receipt.schema";

// ── Request DTOs ─────────────────────────────────────────────────────────────

export class GetReceiptByTxDto {
  @IsString()
  txHash: string;

  @IsOptional()
  @IsInt()
  @Min(0)
  operationIndex?: number;
}

export class GetReceiptsByAddressDto {
  @IsString()
  address: string;

  @IsOptional()
  @IsIn(["payment", "refund", "contract_action"])
  type?: "payment" | "refund" | "contract_action";

  @IsOptional()
  @IsIn(["success", "pending", "failed"])
  status?: "success" | "pending" | "failed";

  @IsOptional()
  @IsInt()
  @Min(1)
  limit?: number;

  @IsOptional()
  @IsString()
  cursor?: string;
}

/**
 * DTO for verifying a receipt hash against canonical inputs.
 * Used by support tooling and indexers to validate receipt integrity.
 */
export class VerifyReceiptHashDto {
  /** The receipt hash to verify (format: rch_<64 hex chars>) */
  @IsString()
  receiptHash: string;

  /** Transaction hash */
  @IsString()
  txHash: string;

  /** Operation index within the transaction */
  @IsInt()
  @Min(0)
  operationIndex: number;

  /** Sender Stellar public key */
  @IsString()
  sourceAccount: string;

  /** Receiver Stellar public key (empty string if none) */
  @IsString()
  destAccount: string;

  /** Exact amount string */
  @IsString()
  amount: string;

  /** Asset code (XLM, USDC, etc.) */
  @IsString()
  assetCode: string;

  /** Asset issuer (empty string for native XLM) */
  @IsString()
  assetIssuer: string;

  /** Ledger sequence number */
  @IsInt()
  @Min(0)
  ledger: number;

  /** Network identifier */
  @IsString()
  @IsIn(["testnet", "mainnet"])
  network: "testnet" | "mainnet";
}

// ── Response DTOs ─────────────────────────────────────────────────────────────

export interface ReceiptResponse {
  receipt: NormalizedReceipt;
}

export interface ReceiptListResponse {
  receipts: NormalizedReceipt[];
  nextCursor: string | null;
  total: number;
}

export interface VerifyReceiptHashResponse {
  /** Whether the provided hash matches the canonical inputs */
  valid: boolean;
  /** The computed hash from the provided inputs */
  computedHash: string;
  /** The hash that was provided for verification */
  providedHash: string;
}
