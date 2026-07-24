import { ApiPropertyOptional } from '@nestjs/swagger';
import { IsOptional, IsString, IsInt, Min, Max } from 'class-validator';
import { Type } from 'class-transformer';
import { PAGINATION_DEFAULTS } from '../../common/pagination/cursor.util';

/**
 * Supported feed item types — each maps to a distinct data source.
 */
export enum FeedItemType {
  PAYMENT = 'payment',
  REFUND = 'refund',
  NOTIFICATION = 'notification',
  CONTRACT_ACTION = 'contract_action',
  USERNAME_CLAIM = 'username_claim',
  WEBHOOK_DELIVERY = 'webhook_delivery',
}

/**
 * Query parameters for the dashboard activity feed.
 */
export class FeedQueryDto {
  @ApiPropertyOptional({
    description: 'Stellar public key of the user whose feed to return',
    example: 'GABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234',
  })
  @IsOptional()
  @IsString()
  publicKey?: string;

  @ApiPropertyOptional({
    description:
      'Comma-separated feed item types to include. Omit for all types.',
    example: 'payment,refund,notification',
  })
  @IsOptional()
  @IsString()
  types?: string;

  @ApiPropertyOptional({
    description: 'Opaque cursor for the next page of results',
    example:
      'eyJwayI6IjIwMjYtMDEtMDFUMDA6MDA6MDAuMDAwWiIsImlkIjoicGF5XzEyMzQ1Njc4In0',
  })
  @IsOptional()
  @IsString()
  cursor?: string;

  @ApiPropertyOptional({
    description: 'Maximum number of items to return per page',
    minimum: PAGINATION_DEFAULTS.LIMIT_MIN,
    maximum: PAGINATION_DEFAULTS.LIMIT_MAX,
    default: PAGINATION_DEFAULTS.LIMIT_DEFAULT,
    example: 20,
  })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(PAGINATION_DEFAULTS.LIMIT_MIN)
  @Max(PAGINATION_DEFAULTS.LIMIT_MAX)
  limit?: number = PAGINATION_DEFAULTS.LIMIT_DEFAULT;
}
