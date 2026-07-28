import { ApiPropertyOptional } from '@nestjs/swagger';
import { IsOptional, IsString, IsIn } from 'class-validator';
import { CursorPaginationQueryDto } from '../../dto/pagination/pagination.dto';
import type { FeedItemKind } from '../dashboard-feed.types';

const FEED_KINDS: FeedItemKind[] = [
  'payment',
  'refund',
  'webhook_delivery',
  'notification',
  'contract_event',
  'username_action',
];

/**
 * Query DTO for the dashboard activity feed endpoint.
 * Extends standard cursor pagination with feed-specific filters.
 */
export class GetFeedQueryDto extends CursorPaginationQueryDto {
  @ApiPropertyOptional({
    description: 'Stellar public key of the account to fetch feed for',
    example: 'GABC1234567890...',
  })
  @IsOptional()
  @IsString()
  address?: string;

  @ApiPropertyOptional({
    description: 'Filter by event kind',
    enum: FEED_KINDS,
  })
  @IsOptional()
  @IsString()
  @IsIn(FEED_KINDS)
  kind?: FeedItemKind;

  @ApiPropertyOptional({
    description: 'Filter events after this ISO-8601 timestamp',
    example: '2026-01-01T00:00:00.000Z',
  })
  @IsOptional()
  @IsString()
  after?: string;

  @ApiPropertyOptional({
    description: 'Filter events before this ISO-8601 timestamp',
    example: '2026-12-31T23:59:59.999Z',
  })
  @IsOptional()
  @IsString()
  before?: string;
}
