import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class PaymentTokenResponseDto {
  @ApiProperty({
    description: 'The payment token value',
    example: 'qt_2xK9mP4rT8wZ7vN1qL5bR3cJ6',
  })
  token!: string;

  @ApiProperty({
    description: 'Token expiry timestamp',
    example: '2026-08-28T12:00:00.000Z',
  })
  expiresAt!: string;

  @ApiProperty({
    description: 'Token status',
    example: 'active',
    enum: ['active', 'consumed', 'revoked', 'expired'],
  })
  status!: string;

  @ApiPropertyOptional({
    description: 'Canonical payment params (for legacy fallback)',
    example: 'amount=50.5000000&asset=XLM&username=john_doe',
  })
  canonical?: string;
}

export class PaymentTokenResolveDto {
  @ApiProperty({
    description: 'Resolved payment context from token',
  })
  paymentContext!: {
    amount: string;
    asset: string;
    username?: string | null;
    destination?: string | null;
    memo?: string | null;
    expiresAt?: string | null;
  };

  @ApiProperty({
    description: 'Token status',
    example: 'active',
  })
  status!: string;
}

export class PaymentTokenRotateDto {
  @ApiProperty({
    description: 'New token value after rotation',
    example: 'qt_9sH2kL5pR7wZ4vN8qM1bT6cJ3',
  })
  newToken!: string;

  @ApiProperty({
    description: 'New token expiry timestamp',
    example: '2026-08-28T12:00:00.000Z',
  })
  expiresAt!: string;

  @ApiProperty({
    description: 'Updated canonical params with new token',
    example: 'token=qt_9sH2kL5pR7wZ4vN8qM1bT6cJ3',
  })
  canonical!: string;
}

export class PaymentTokenRevokeResponseDto {
  @ApiProperty({
    description: 'Whether revocation succeeded',
    example: true,
  })
  success!: boolean;

  @ApiProperty({
    description: 'Revoked token',
    example: 'qt_2xK9mP4rT8wZ7vN1qL5bR3cJ6',
  })
  token!: string;
}

export class PaymentTokenGenerateRequestDto {
  @ApiProperty({
    description: 'Payment amount',
    example: 50.5,
  })
  amount!: number;

  @ApiPropertyOptional({
    description: 'Asset code',
    example: 'XLM',
    default: 'XLM',
  })
  asset?: string;

  @ApiPropertyOptional({
    description: 'QuickEx username (payee)',
    example: 'john_doe',
  })
  username?: string;

  @ApiPropertyOptional({
    description: 'Destination Stellar public key',
    example: 'GABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890',
  })
  destination?: string;

  @ApiPropertyOptional({
    description: 'Payment memo',
    example: 'Invoice #123',
  })
  memo?: string;

  @ApiPropertyOptional({
    description: 'Memo type',
    example: 'text',
    default: 'text',
  })
  memoType?: string;

  @ApiPropertyOptional({
    description: 'Token TTL in seconds (default 86400 = 24h)',
    example: 3600,
    default: 86400,
  })
  ttlSeconds?: number;

  @ApiPropertyOptional({
    description: 'Accepted asset codes for multi-asset support',
    example: ['XLM', 'USDC'],
  })
  acceptedAssets?: string[];
}
