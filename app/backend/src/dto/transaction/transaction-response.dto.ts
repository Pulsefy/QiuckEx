import { ApiProperty } from '@nestjs/swagger';

/**
 * Individual transaction in the response
 */
export class TransactionDto {
  @ApiProperty( {
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
    example: 'GA5ZSEJYB37JRC5AVCIA5MOP4RhTM335X2KGX3IHOJAPP5RE34K4KZVN',
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
 * Response for submitting a signed transaction to the network
 */
export class SubmitTransactionResponseDto {
  @ApiProperty({
    description: 'Network-assigned transaction hash',
    example: '3389c7b3ed4a5f607b7a8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f45a6b7c8d9e0',
  })
  hash!: string;

  @ApiProperty({
    description: 'Ledger sequence the transaction was included in (0 if not yet confirmed)',
    example: 12345678,
  })
  ledger!: number;

  @ApiProperty({
    description: 'Submission status',
    example: 'PENDING',
    enum: ['PENDING', 'SUCCESS', 'FAILED'],
  })
  status!: 'PENDING' | 'SUCCESS' | 'FAILED';

  @ApiProperty({
    description: 'Result code returned by the network (if failed)',
    example: 'tx_bad_seq',
    nullable: true,
  })
  resultCode!: string | null;

  @ApiProperty({
    description: 'Human-readable message describing the submission outcome',
    example: 'Transaction submitted to the network',
  })
  message!: string;
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
 *       "destinationAccount": "G*ABC123...",
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
