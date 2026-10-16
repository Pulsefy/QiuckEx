/**
 * DTOs for the receipt normalization API.
 *
 * Location: app/backend/src/receipts/dto/receipt.dto.ts
 */

import { ApiProperty, ApiPropertyOptional } from "@nestjs/swagger";
import { IsString, IsIn, IsOptional, IsInt, Min } from "class-validator";
import {
  NormalizedReceipt,
  PartyInfo,
  StellarAsset,
  FeeMetadata,
  ContractMeta,
  DiagnosticMeta,
  ReceiptType,
  ReceiptStatus,
} from "../schemas/receipt.schema";

// ── Request DTOs ─────────────────────────────────────────────────────────────

export class GetReceiptByTxDto {
  @ApiProperty({ description: "Stellar transaction hash", example: "4a8c1..." })
  @IsString()
  txHash: string;

  @ApiPropertyOptional({ description: "Operation index within transaction", default: 0, example: 0 })
  @IsOptional()
  @IsInt()
  @Min(0)
  operationIndex?: number;
}

export class GetReceiptsByAddressDto {
  @ApiProperty({ description: "Stellar account address", example: "GDG..." })
  @IsString()
  address: string;

  @ApiPropertyOptional({ description: "Receipt type filter", enum: ["payment", "refund", "contract_action"] })
  @IsOptional()
  @IsIn(["payment", "refund", "contract_action"])
  type?: "payment" | "refund" | "contract_action";

  @ApiPropertyOptional({ description: "Receipt status filter", enum: ["success", "pending", "failed"] })
  @IsOptional()
  @IsIn(["success", "pending", "failed"])
  status?: "success" | "pending" | "failed";

  @ApiPropertyOptional({ description: "Maximum results", default: 20, example: 20 })
  @IsOptional()
  @IsInt()
  @Min(1)
  limit?: number;

  @ApiPropertyOptional({ description: "Pagination cursor token" })
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
  @ApiProperty({ description: "Receipt hash format rch_<64 hex chars>", example: "rch_a1b2..." })
  @IsString()
  receiptHash: string;

  /** Transaction hash */
  @ApiProperty({ description: "Transaction hash", example: "4a8c1..." })
  @IsString()
  txHash: string;

  /** Operation index within the transaction */
  @ApiProperty({ description: "Operation index", example: 0 })
  @IsInt()
  @Min(0)
  operationIndex: number;

  /** Sender Stellar public key */
  @ApiProperty({ description: "Sender public key", example: "GAA..." })
  @IsString()
  sourceAccount: string;

  /** Receiver Stellar public key (empty string if none) */
  @ApiProperty({ description: "Receiver public key", example: "GBB..." })
  @IsString()
  destAccount: string;

  /** Exact amount string */
  @ApiProperty({ description: "Exact amount string", example: "100.00" })
  @IsString()
  amount: string;

  /** Asset code (XLM, USDC, etc.) */
  @ApiProperty({ description: "Asset code", example: "USDC" })
  @IsString()
  assetCode: string;

  /** Asset issuer (empty string for native XLM) */
  @ApiProperty({ description: "Asset issuer", example: "GBBD..." })
  @IsString()
  assetIssuer: string;

  /** Ledger sequence number */
  @ApiProperty({ description: "Ledger sequence number", example: 123456 })
  @IsInt()
  @Min(0)
  ledger: number;

  /** Network identifier */
  @ApiProperty({ description: "Network identifier", enum: ["testnet", "mainnet"], example: "testnet" })
  @IsString()
  @IsIn(["testnet", "mainnet"])
  network: "testnet" | "mainnet";
}

// ── Response DTOs ─────────────────────────────────────────────────────────────

export class PartyInfoDto implements PartyInfo {
  @ApiProperty({ description: "Stellar account address", example: "GAA..." })
  address: string;

  @ApiProperty({ description: "Resolved QuickEx username or null", nullable: true, example: "alice" })
  username: string | null;
}

export class StellarAssetDto implements StellarAsset {
  @ApiProperty({ description: "Asset type", enum: ["native", "credit_alphanum4", "credit_alphanum12"], example: "native" })
  type: "native" | "credit_alphanum4" | "credit_alphanum12";

  @ApiProperty({ description: "Asset code", example: "XLM" })
  code: string;

  @ApiProperty({ description: "Asset issuer address or null for native", nullable: true, example: null })
  issuer: string | null;
}

export class FeeMetadataDto implements FeeMetadata {
  @ApiProperty({ description: "Base fee in stroops", example: "100" })
  baseFeeSatoshis: string;

  @ApiProperty({ description: "Total fee in stroops", example: "100" })
  totalFeeSatoshis: string;

  @ApiProperty({ description: "Fee in XLM", example: "0.00001" })
  feeXlm: string;
}

export class DiagnosticMetaDto implements DiagnosticMeta {
  @ApiProperty({ description: "Stellar error code or null", nullable: true })
  errorCode: string | null;

  @ApiProperty({ description: "Human readable error message or null", nullable: true })
  errorMessage: string | null;

  @ApiProperty({ description: "Raw result XDR or null", nullable: true })
  resultXdr: string | null;

  @ApiProperty({ description: "Raw envelope XDR or null", nullable: true })
  envelopeXdr: string | null;
}

export class NormalizedReceiptDto implements NormalizedReceipt {
  @ApiProperty({ description: "Stable receipt identifier", example: "rcpt_abc123_0" })
  receiptId: string;

  @ApiProperty({ description: "Deterministic SHA-256 receipt hash", example: "rch_a1b2..." })
  receiptHash: string;

  @ApiProperty({ description: "Transaction hash", example: "4a8c..." })
  txHash: string;

  @ApiProperty({ description: "Operation index within transaction", example: 0 })
  operationIndex: number;

  @ApiProperty({ description: "Receipt type", enum: ["payment", "refund", "contract_action"], example: "payment" })
  type: ReceiptType;

  @ApiProperty({ description: "Receipt status", enum: ["success", "pending", "failed"], example: "success" })
  status: ReceiptStatus;

  @ApiProperty({ description: "On-chain contract receipt reference or null", nullable: true })
  receiptReference: string | null;

  @ApiProperty({ description: "Creation ISO timestamp", example: "2026-01-01T00:00:00.000Z" })
  createdAt: string;

  @ApiProperty({ description: "Last update ISO timestamp", example: "2026-01-01T00:00:00.000Z" })
  updatedAt: string;

  @ApiProperty({ description: "Ledger sequence number or null", nullable: true, example: 123456 })
  ledger: number | null;

  @ApiProperty({ description: "Sender details", type: PartyInfoDto })
  sender: PartyInfoDto;

  @ApiProperty({ description: "Receiver details or null", type: PartyInfoDto, nullable: true })
  receiver: PartyInfoDto | null;

  @ApiProperty({ description: "Asset metadata", type: StellarAssetDto })
  asset: StellarAssetDto;

  @ApiProperty({ description: "Exact amount string", example: "10.00" })
  amount: string;

  @ApiProperty({ description: "Human display amount", example: "10.00 XLM" })
  displayAmount: string;

  @ApiProperty({ description: "Transaction memo or null", nullable: true })
  memo: string | null;

  @ApiProperty({ description: "Memo type", enum: ["text", "id", "hash", "return", "none"], example: "text" })
  memoType: "text" | "id" | "hash" | "return" | "none";

  @ApiProperty({ description: "Fee details", type: FeeMetadataDto })
  fee: FeeMetadataDto;

  @ApiProperty({ description: "Contract action metadata or null", nullable: true, type: Object })
  contract: ContractMeta | null;

  @ApiProperty({ description: "Diagnostic error information", type: DiagnosticMetaDto })
  diagnostic: DiagnosticMetaDto;

  @ApiProperty({ description: "Network identifier", enum: ["testnet", "mainnet"], example: "testnet" })
  network: "testnet" | "mainnet";

  @ApiProperty({ description: "Explorer URL", example: "https://stellar.expert/..." })
  explorerUrl: string;
}

export class ReceiptResponse {
  @ApiProperty({ type: NormalizedReceiptDto, description: "Normalized receipt payload" })
  receipt: NormalizedReceiptDto;
}

export class ReceiptListResponse {
  @ApiProperty({ type: [NormalizedReceiptDto], description: "List of normalized receipts" })
  receipts: NormalizedReceiptDto[];

  @ApiProperty({ description: "Paging token for next page or null", nullable: true, example: null })
  nextCursor: string | null;

  @ApiProperty({ description: "Total count of matching receipts", example: 1 })
  total: number;
}

export class VerifyReceiptHashResponse {
  @ApiProperty({ description: "Whether the provided hash matches the canonical inputs", example: true })
  valid: boolean;

  @ApiProperty({ description: "The computed hash from the provided inputs", example: "rch_a1b2..." })
  computedHash: string;

  @ApiProperty({ description: "The hash that was provided for verification", example: "rch_a1b2..." })
  providedHash: string;
}

