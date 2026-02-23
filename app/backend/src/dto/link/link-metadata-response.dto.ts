import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

/**
 * Response DTO for link metadata
 * 
 * @example
 * ```json
 * {
 *   "amount": "50.5000000",
 *   "memo": "Payment for service",
 *   "memoType": "text",
 *   "asset": "XLM",
 *   "privacy": false,
 *   "expiresAt": "2026-02-24T12:00:00.000Z",
 *   "canonical": "amount=50.5000000&asset=XLM&memo=Payment%20for%20service",
 *   "metadata": {
 *     "normalized": false
 *   }
 * }
 * ```
 */
export class LinkMetadataResponseDto {
  @ApiProperty({
    description: 'Normalized amount with 7 decimal places',
    example: '50.5000000',
  })
  amount!: string;

  @ApiProperty({
    description: 'Sanitized memo text',
    example: 'Payment for service',
    nullable: true,
  })
  memo!: string | null;

  @ApiProperty({
    description: 'Memo type',
    example: 'text',
  })
  memoType!: string;

  @ApiProperty({
    description: 'Asset code',
    example: 'XLM',
  })
  asset!: string;

  @ApiProperty({
    description: 'Privacy flag',
    example: false,
  })
  privacy!: boolean;

  @ApiProperty({
    description: 'Expiration date',
    example: '2026-02-24T12:00:00.000Z',
    nullable: true,
  })
  expiresAt!: Date | null;

  @ApiProperty({
    description: 'Canonical link format',
    example: 'amount=50.5000000&asset=XLM&memo=Payment%20for%20service',
  })
  canonical!: string;

  @ApiPropertyOptional({
    description: 'Username associated with the payment link',
    example: 'john_doe123',
    nullable: true,
  })
  username?: string | null;

  @ApiPropertyOptional({
    description: 'Destination Stellar account public key',
    example: 'GABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890',
    nullable: true,
  })
  destination?: string | null;

  @ApiPropertyOptional({
    description: 'Custom reference ID for tracking',
    example: 'INV-12345',
    nullable: true,
  })
  referenceId?: string | null;

  @ApiProperty({
    description: 'Metadata information',
    example: {
      normalized: false,
      assetType: 'native',
      linkType: 'standard',
      securityLevel: 'medium',
    },
  })
  metadata!: {
    normalized: boolean;
    warnings?: string[];
    [key: string]: unknown;
  };
}
