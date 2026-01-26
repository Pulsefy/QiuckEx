import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsString,
  IsOptional,
  IsInt,
  Min,
  Max,
  IsEnum,
  IsDateString,
} from 'class-validator';
import { Type } from 'class-transformer';

import { IsStellarPublicKey, IsStellarAsset } from '../validators';

/**
 * Transaction query sort order
 */
export enum TransactionSortOrder {
  ASC = 'asc',
  DESC = 'desc',
}

/**
 * DTO for querying transactions
 * 
 * Supports filtering and pagination for Stellar transaction queries.
 * 
 * @example
 * ```json
 * {
 *   "account": "GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR",
 *   "asset": "XLM",
 *   "limit": 20,
 *   "cursor": "1234567890",
 *   "order": "desc",
 *   "fromDate": "2026-01-01T00:00:00Z",
 *   "toDate": "2026-01-31T23:59:59Z"
 * }
 * ```
 */
export class TransactionQueryDto {
  @ApiPropertyOptional({
    description: 'Stellar account public key to filter transactions',
    example: 'GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR',
  })
  @IsOptional()
  @IsString()
  @IsStellarPublicKey({
    message: 'Account must be a valid Stellar public key',
  })
  account?: string;

  @ApiPropertyOptional({
    description: 'Asset code to filter transactions',
    example: 'XLM',
    enum: ['XLM', 'USDC', 'AQUA', 'yXLM'],
  })
  @IsOptional()
  @IsString()
  @IsStellarAsset({
    message: 'Asset must be one of: XLM, USDC, AQUA, yXLM',
  })
  asset?: string;

  @ApiPropertyOptional({
    description: 'Maximum number of transactions to return',
    example: 20,
    minimum: 1,
    maximum: 200,
    default: 20,
  })
  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(200)
  @Type(() => Number)
  limit?: number;

  @ApiPropertyOptional({
    description: 'Pagination cursor (transaction ID or sequence number)',
    example: '1234567890',
  })
  @IsOptional()
  @IsString()
  cursor?: string;

  @ApiPropertyOptional({
    description: 'Sort order for transactions',
    example: 'desc',
    enum: TransactionSortOrder,
    default: TransactionSortOrder.DESC,
  })
  @IsOptional()
  @IsEnum(TransactionSortOrder)
  order?: TransactionSortOrder;

  @ApiPropertyOptional({
    description: 'Start date for transaction filter (ISO 8601)',
    example: '2026-01-01T00:00:00Z',
  })
  @IsOptional()
  @IsDateString()
  fromDate?: string;

  @ApiPropertyOptional({
    description: 'End date for transaction filter (ISO 8601)',
    example: '2026-01-31T23:59:59Z',
  })
  @IsOptional()
  @IsDateString()
  toDate?: string;
}
