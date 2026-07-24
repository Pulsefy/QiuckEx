import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { FeedItemType } from './feed-query.dto';

/**
 * Type-specific payload for each kind of feed item.
 * The schema is intentionally loose so the frontend can evolve
 * independently; the service guarantees stable field shapes per type.
 */

export interface PaymentFeedData {
  amount: string;
  asset: string;
  status: 'Success' | 'Pending' | 'Failed';
  sender: string;
  receiver: string | null;
  txHash: string;
  memo: string | null;
}

export interface RefundFeedData {
  refundId: string;
  entityType: string;
  entityId: string;
  status: string;
  reasonCode: string | null;
  actorId: string;
}

export interface NotificationFeedData {
  eventType: string;
  eventId: string;
  title: string;
  body: string;
  read: boolean;
  metadata: Record<string, unknown> | null;
}

export interface ContractActionFeedData {
  contractId: string;
  functionName: string;
  txHash: string;
  status: 'success' | 'pending' | 'failed';
  resourceFee: string | null;
}

export interface UsernameClaimFeedData {
  username: string;
  publicKey: string;
}

export interface WebhookDeliveryFeedData {
  webhookUrl: string;
  eventType: string;
  eventId: string;
  status: 'sent' | 'failed';
  httpStatus: number | null;
  errorMessage: string | null;
}

export type FeedItemData =
  | PaymentFeedData
  | RefundFeedData
  | NotificationFeedData
  | ContractActionFeedData
  | UsernameClaimFeedData
  | WebhookDeliveryFeedData;

/**
 * A single item in the unified dashboard activity feed.
 */
export class FeedItemDto {
  @ApiProperty({
    description: 'Unique ID of this feed item, prefixed by type for global uniqueness',
    example: 'pay_12345678-abcd-1234-5678-1234567890ab',
  })
  id: string;

  @ApiProperty({
    description: 'Category of this feed item',
    enum: FeedItemType,
    example: FeedItemType.PAYMENT,
  })
  type: FeedItemType;

  @ApiProperty({
    description: 'ISO-8601 timestamp when the event occurred',
    example: '2026-07-24T12:00:00.000Z',
  })
  timestamp: string;

  @ApiProperty({
    description: 'Type-specific payload with fields stable per type',
  })
  data: FeedItemData;

  @ApiPropertyOptional({
    description: 'Optional human-readable title for rendering',
    example: 'Payment received: 100.00 XLM',
  })
  title?: string;

  @ApiPropertyOptional({
    description: 'Optional human-readable description',
    example: 'From GABCD...5678',
  })
  description?: string;
}

/**
 * Cursor-based pagination metadata.
 */
export class FeedPaginationMetaDto {
  @ApiPropertyOptional({
    description: 'Opaque cursor to fetch the next page. Null if no more results.',
    nullable: true,
  })
  next_cursor: string | null;

  @ApiProperty({
    description: 'Whether there are more results beyond this page',
    example: true,
  })
  has_more: boolean;

  @ApiProperty({
    description: 'The limit used for this page',
    example: 20,
  })
  limit: number;
}

/**
 * Envelope for the dashboard activity feed response.
 */
export class FeedResponseDto {
  @ApiProperty({
    description: 'Array of feed items in reverse chronological order',
    type: [FeedItemDto],
  })
  items: FeedItemDto[];

  @ApiProperty({
    description: 'Pagination metadata for cursor-based navigation',
    type: FeedPaginationMetaDto,
  })
  pagination: FeedPaginationMetaDto;
}
