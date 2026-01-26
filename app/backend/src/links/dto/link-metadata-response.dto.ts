import { ApiProperty } from '@nestjs/swagger';

export class LinkMetadataResponseDto {
  @ApiProperty({
    description: 'Normalized amount with 7 decimal places',
    example: '50.5000000',
  })
  amount: string;

  @ApiProperty({
    description: 'Sanitized memo text',
    example: 'Payment for service',
    nullable: true,
  })
  memo: string | null;

  @ApiProperty({
    description: 'Memo type',
    example: 'text',
  })
  memoType: string;

  @ApiProperty({
    description: 'Asset code',
    example: 'XLM',
  })
  asset: string;

  @ApiProperty({
    description: 'Privacy flag',
    example: false,
  })
  privacy: boolean;

  @ApiProperty({
    description: 'Expiration date',
    example: '2026-02-24T12:00:00.000Z',
    nullable: true,
  })
  expiresAt: Date | null;

  @ApiProperty({
    description: 'Canonical link format',
    example: 'amount=50.5000000&asset=XLM&memo=Payment%20for%20service',
  })
  canonical: string;

  @ApiProperty({
    description: 'Metadata information',
    example: {
      normalized: false,
    },
  })
  metadata: {
    normalized: boolean;
    warnings?: string[];
  };
}
