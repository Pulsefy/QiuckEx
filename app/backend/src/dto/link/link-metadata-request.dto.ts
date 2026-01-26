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
  STELLAR_MEMO,
  STELLAR_AMOUNT,
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
    description: 'Optional memo text (max 28 characters after sanitization)',
    example: 'Payment for service',
    maxLength: STELLAR_MEMO.MAX_LENGTH,
  })
  @IsOptional()
  @IsString()
  // Note: Memo length validation happens in service after sanitization
  // DTO validation only checks it's a string
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
  // Note: Asset whitelist validation happens in service (business logic)
  // DTO validation only checks it's a string
  asset?: string;

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
