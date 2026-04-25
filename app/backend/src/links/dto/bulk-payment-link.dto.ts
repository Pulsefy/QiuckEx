import { ApiProperty } from '@nestjs/swagger';
import {
  IsString,
  IsNumber,
  IsOptional,
  IsBoolean,
  IsArray,
  ValidateNested,
  Min,
  Max,
  Length,
  Matches,
} from 'class-validator';
import { Type } from 'class-transformer';

/**
 * DTO for a single payment link in a bulk generation request
 */
export class BulkPaymentLinkItemDto {
  @ApiProperty({
    description: 'Payment amount',
    example: 100.5,
  })
  @IsNumber()
  @Min(0.0000001)
  @Max(1000000000)
  amount!: number;

  @ApiProperty({
    description: 'Asset code (e.g., XLM, USDC)',
    example: 'XLM',
    required: false,
  })
  @IsString()
  @IsOptional()
  asset?: string;

  @ApiProperty({
    description: 'Payment memo (optional)',
    example: 'Invoice #123',
    required: false,
  })
  @IsString()
  @IsOptional()
  @Length(0, 28)
  memo?: string;

  @ApiProperty({
    description: 'Memo type (text, id, hash, return)',
    example: 'text',
    required: false,
  })
  @IsString()
  @IsOptional()
  @Matches(/^(text|id|hash|return)$/, {
    message: 'Memo type must be one of: text, id, hash, return',
  })
  memoType?: string;

  @ApiProperty({
    description: 'Recipient username (optional)',
    example: 'john_doe',
    required: false,
  })
  @IsString()
  @IsOptional()
  @Length(3, 32)
  username?: string;

  @ApiProperty({
    description: 'Recipient Stellar public key (optional)',
    example: 'GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN',
    required: false,
  })
  @IsString()
  @IsOptional()
  @Matches(/^G[ABCDEFGHIJKLMNOPQRSTUVWXYZ234567]{55}$/, {
    message: 'Destination must be a valid Stellar public key',
  })
  destination?: string;

  @ApiProperty({
    description: 'Reference ID for tracking (optional)',
    example: 'INV-2025-001',
    required: false,
  })
  @IsString()
  @IsOptional()
  @Length(0, 64)
  @Matches(/^[a-zA-Z0-9_-]*$/, {
    message: 'Reference ID must be alphanumeric, hyphens, or underscores',
  })
  referenceId?: string;

  @ApiProperty({
    description: 'Enable privacy mode (X-Ray)',
    example: false,
    required: false,
  })
  @IsBoolean()
  @IsOptional()
  privacy?: boolean;

  @ApiProperty({
    description: 'Link expiration in days',
    example: 30,
    required: false,
  })
  @IsNumber()
  @IsOptional()
  @Min(1)
  @Max(365)
  expirationDays?: number;

  @ApiProperty({
    description: 'Accepted assets for payment (optional)',
    example: ['XLM', 'USDC'],
    required: false,
  })
  @IsArray()
  @IsString({ each: true })
  @IsOptional()
  acceptedAssets?: string[];
}

/**
 * DTO for bulk payment link generation request (JSON)
 */
export class BulkPaymentLinkRequestDto {
  @ApiProperty({
    description: 'Array of payment link items to generate',
    type: [BulkPaymentLinkItemDto],
  })
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => BulkPaymentLinkItemDto)
  links!: BulkPaymentLinkItemDto[];
}

/**
 * DTO for a single generated payment link response
 */
export class BulkPaymentLinkResponseItemDto {
  @ApiProperty({
    description: 'Unique link identifier',
    example: 'link_abc123',
  })
  id!: string;

  @ApiProperty({
    description: 'Canonical payment link format',
    example: 'amount=100.5000000&asset=XLM&memo=Invoice%20%23123&username=john_doe',
  })
  canonical!: string;

  @ApiProperty({
    description: 'Shareable payment link URL',
    example: 'https://app.quickex.example.com/pay?amount=100.5000000&asset=XLM',
  })
  url!: string;

  @ApiProperty({
    description: 'Payment amount',
    example: '100.5000000',
  })
  amount!: string;

  @ApiProperty({
    description: 'Asset code',
    example: 'XLM',
  })
  asset!: string;

  @ApiProperty({
    description: 'Recipient username (if provided)',
    example: 'john_doe',
    required: false,
  })
  username?: string;

  @ApiProperty({
    description: 'Recipient destination (if provided)',
    example: 'GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN',
    required: false,
  })
  destination?: string;

  @ApiProperty({
    description: 'Reference ID (if provided)',
    example: 'INV-2025-001',
    required: false,
  })
  referenceId?: string;

  @ApiProperty({
    description: 'Index in the original request',
    example: 0,
  })
  index!: number;
}

/**
 * DTO for bulk payment link generation response
 */
export class BulkPaymentLinkResponseDto {
  @ApiProperty({
    description: 'Success status',
    example: true,
  })
  success!: boolean;

  @ApiProperty({
    description: 'Total number of links generated',
    example: 100,
  })
  total!: number;

  @ApiProperty({
    description: 'Generated payment links',
    type: [BulkPaymentLinkResponseItemDto],
  })
  links!: BulkPaymentLinkResponseItemDto[];

  @ApiProperty({
    description: 'Processing time in milliseconds',
    example: 245,
  })
  processingTimeMs!: number;
}
