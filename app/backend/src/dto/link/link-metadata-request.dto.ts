import {
  IsNumber,
  IsString,
  IsBoolean,
  IsOptional,
  Min,
  Max,
} from 'class-validator';
import { Type } from 'class-transformer';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

import {
  IsStellarAmount,
  IsStellarMemo,
  IsStellarAsset,
  STELLAR_MEMO,
  STELLAR_AMOUNT,
  AssetCode,
  MemoType,
} from '../validators';

/**
 * DTO for link metadata request
 * 
 * Validates payment link parameters according to Stellar network constraints.
 * 
 * @example
 * ```json
 * {
 *   "amount": 50.5,
 *   "memo": "Payment for service",
 *   "memoType": "text",
 *   "asset": "XLM",
 *   "privacy": false,
 *   "expirationDays": 30
 * }
 * ```
 */
export class LinkMetadataRequestDto {
  @ApiProperty({
    description: 'Payment amount in specified asset',
    example: 50.5,
    minimum: STELLAR_AMOUNT.MIN,
    maximum: STELLAR_AMOUNT.MAX,
  })
  @IsNumber()
  @IsStellarAmount({
    message: `Amount must be between ${STELLAR_AMOUNT.MIN} and ${STELLAR_AMOUNT.MAX}`,
  })
  @Type(() => Number)
  amount!: number;

  @ApiPropertyOptional({
    description: 'Optional memo text (max 28 characters)',
    example: 'Payment for service',
    maxLength: STELLAR_MEMO.MAX_LENGTH,
  })
  @IsOptional()
  @IsString()
  @IsStellarMemo({
    message: `Memo must be at most ${STELLAR_MEMO.MAX_LENGTH} characters`,
  })
  memo?: string;

  @ApiPropertyOptional({
    description: 'Memo type',
    example: 'text',
    enum: STELLAR_MEMO.ALLOWED_TYPES,
  })
  @IsOptional()
  @IsString()
  memoType?: MemoType;

  @ApiPropertyOptional({
    description: 'Asset code',
    example: 'XLM',
    enum: ['XLM', 'USDC', 'AQUA', 'yXLM'],
  })
  @IsOptional()
  @IsString()
  @IsStellarAsset({
    message: 'Asset must be one of: XLM, USDC, AQUA, yXLM',
  })
  asset?: AssetCode;

  @ApiPropertyOptional({
    description: 'Privacy flag',
    example: false,
  })
  @IsOptional()
  @IsBoolean()
  @Type(() => Boolean)
  privacy?: boolean;

  @ApiPropertyOptional({
    description: 'Expiration in days',
    example: 30,
    minimum: 1,
    maximum: 365,
  })
  @IsOptional()
  @IsNumber()
  @Min(1)
  @Max(365)
  @Type(() => Number)
  expirationDays?: number;
}
