/**
 * DTOs for the receipt normalization API.
 *
 * Location: app/backend/src/receipts/dto/receipt.dto.ts
 */

import { IsString, IsIn, IsOptional, IsInt, Min } from 'class-validator';
import { NormalizedReceipt } from '../schemas/receipt.schema';

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
  @IsIn(['payment', 'refund', 'contract_action'])
  type?: 'payment' | 'refund' | 'contract_action';

  @IsOptional()
  @IsIn(['success', 'pending', 'failed'])
  status?: 'success' | 'pending' | 'failed';

  @IsOptional()
  @IsInt()
  @Min(1)
  limit?: number;

  @IsOptional()
  @IsString()
  cursor?: string;
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