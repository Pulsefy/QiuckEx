import {
  IsNumber,
  IsString,
  IsBoolean,
  IsOptional,
  Min,
  Max,
  Matches,
  Validate,
  ValidateIf,
} from 'class-validator';
import { Type } from 'class-transformer';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

import {
  IsStellarAmount,
  STELLAR_MEMO,
  STELLAR_AMOUNT,
  MemoType,
  IsStellarAsset,
  STELLAR_ASSETS,
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
    description: 'Asset code (must be whitelisted: XLM, USDC, AQUA, yXLM)',
    example: 'XLM',
    enum: ['XLM', 'USDC', 'AQUA', 'yXLM'],
  })
  @IsOptional()
  @IsString()
  @Validate(IsStellarAsset, {
    message: `Asset must be one of: ${STELLAR_ASSETS.join(', ')}`,
  })
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

  @ApiPropertyOptional({
    description: 'Username for the payment link (must follow username pattern)',
    example: 'john_doe123',
    pattern: '^[a-z0-9][a-z0-9_-]{2,30}[a-z0-9]$|^[a-z0-9]{1,32}$',
  })
  @IsOptional()
  @IsString()
  @Matches(/^[a-z0-9][a-z0-9_-]{2,30}[a-z0-9]$|^[a-z0-9]{1,32}$/, {
    message: 'Username must be 1-32 lowercase alphanumeric characters, may include hyphens and underscores, but cannot start or end with special characters',
  })
  username?: string;

  @ApiPropertyOptional({
    description: 'Destination Stellar account public key',
    example: 'GABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890',
  })
  @IsOptional()
  @IsString()
  @ValidateIf((object: LinkMetadataRequestDto) => object.destination !== undefined)
  @Matches(/^G[ABCDEFGHIJKLMNOPQRSTUVWXYZ234567]{55}$/, {
    message: 'Destination must be a valid Stellar public key (starts with G, 56 characters)',
  })
  destination?: string;

  @ApiPropertyOptional({
    description: 'Custom reference ID for tracking',
    example: 'INV-12345',
    maxLength: 64,
  })
  @IsOptional()
  @IsString()
  @Matches(/^[a-zA-Z0-9_-]{1,64}$/, {
    message: 'Reference ID must be 1-64 alphanumeric characters, hyphens, or underscores',
  })
  referenceId?: string;
}
