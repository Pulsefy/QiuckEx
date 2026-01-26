import { ApiProperty } from '@nestjs/swagger';

/**
 * Individual transaction in the response
 */
export class TransactionDto {
  @ApiProperty({
    description: 'Transaction hash',
    example: 'abc123def456...',
  })
  hash!: string;

  @ApiProperty({
    description: 'Transaction ledger sequence number',
    example: 12345678,
  })
  ledger!: number;

  @ApiProperty({
    description: 'Transaction timestamp (ISO 8601)',
    example: '2026-01-25T12:00:00Z',
  })
  timestamp!: string;

  @ApiProperty({
    description: 'Source account public key',
    example: 'GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR',
  })
  sourceAccount!: string;

  @ApiProperty({
    description: 'Transaction type',
    example: 'payment',
  })
  type!: string;

  @ApiProperty({
    description: 'Asset code',
    example: 'XLM',
    nullable: true,
  })
  assetCode!: string | null;

  @ApiProperty({
    description: 'Asset issuer (for non-native assets)',
    example: 'GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN',
    nullable: true,
  })
  assetIssuer!: string | null;

  @ApiProperty({
    description: 'Transaction amount',
    example: '100.5000000',
  })
  amount!: string;

  @ApiProperty({
    description: 'Destination account public key',
    example: 'GABC123...',
    nullable: true,
  })
  destinationAccount!: string | null;

  @ApiProperty({
    description: 'Transaction memo',
    example: 'Payment for service',
    nullable: true,
  })
  memo!: string | null;

  @ApiProperty({
    description: 'Transaction memo type',
    example: 'text',
    nullable: true,
  })
  memoType!: string | null;
}

/**
 * Response DTO for transaction queries
 * 
 * @example
 * ```json
 * {
 *   "transactions": [
 *     {
 *       "hash": "abc123...",
 *       "ledger": 12345678,
 *       "timestamp": "2026-01-25T12:00:00Z",
 *       "sourceAccount": "GBXGQ...",
 *       "type": "payment",
 *       "assetCode": "XLM",
 *       "assetIssuer": null,
 *       "amount": "100.5000000",
 *       "destinationAccount": "GABC123...",
 *       "memo": "Payment for service",
 *       "memoType": "text"
 *     }
 *   ],
 *   "pagination": {
 *     "limit": 20,
 *     "cursor": "1234567890",
 *     "hasMore": true
 *   }
 * }
 * ```
 */
export class TransactionResponseDto {
  @ApiProperty({
    description: 'List of transactions',
    type: [TransactionDto],
  })
  transactions!: TransactionDto[];

  @ApiProperty({
    description: 'Pagination information',
    example: {
      limit: 20,
      cursor: '1234567890',
      hasMore: true,
    },
  })
  pagination!: {
    limit: number;
    cursor?: string;
    hasMore: boolean;
  };
}
