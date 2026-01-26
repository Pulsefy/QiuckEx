import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsString, IsNumber, IsOptional, Min } from 'class-validator';
import { Type } from 'class-transformer';

import {
  IsStellarAmount,
  IsStellarAsset,
  IsStellarPublicKey,
  IsStellarMemo,
} from '../validators';

/**
 * DTO for scanning a payment link for scam indicators
 * 
 * @example
 * ```json
 * {
 *   "assetCode": "USDC",
 *   "amount": 100.5,
 *   "memo": "Invoice-12345",
 *   "recipientAddress": "GABC123..."
 * }
 * ```
 */
export class ScanLinkDto {
  @ApiProperty({
    description: 'Asset code to be transferred',
    example: 'USDC',
  })
  @IsString()
  @IsStellarAsset({
    message: 'Asset code must be one of: XLM, USDC, AQUA, yXLM',
  })
  assetCode!: string;

  @ApiProperty({
    description: 'Amount to be transferred',
    example: 100.5,
  })
  @IsNumber()
  @IsStellarAmount({
    message: 'Amount must be a valid Stellar amount',
  })
  @Type(() => Number)
  amount!: number;

  @ApiPropertyOptional({
    description: 'Optional memo/reference for the payment',
    example: 'Invoice-12345',
  })
  @IsString()
  @IsOptional()
  @IsStellarMemo({
    message: 'Memo must be at most 28 characters',
  })
  memo?: string;

  @ApiPropertyOptional({
    description: 'Optional recipient address for additional verification',
    example: 'GABC123...',
  })
  @IsString()
  @IsOptional()
  @IsStellarPublicKey({
    message: 'Recipient address must be a valid Stellar public key',
  })
  recipientAddress?: string;
}
