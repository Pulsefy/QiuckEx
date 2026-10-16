import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { FeedItemKind, FeedItemStatus } from './dashboard-feed.types';

export class PaymentFeedDetailDto {
  @ApiProperty({ description: 'Transaction hash', example: '4a8c...' })
  txHash: string;

  @ApiProperty({ description: 'Amount string', example: '10.50' })
  amount: string;

  @ApiProperty({ description: 'Asset code', example: 'USDC' })
  asset: string;

  @ApiProperty({ description: 'Sender Stellar public key', example: 'GAA...' })
  sender: string;

  @ApiProperty({ description: 'Receiver Stellar public key', example: 'GBB...' })
  receiver: string;

  @ApiProperty({ description: 'Payment status', example: 'success' })
  status: string;
}

export class RefundFeedDetailDto {
  @ApiProperty({ description: 'Refund ID', example: 'ref_123' })
  refundId: string;

  @ApiProperty({ description: 'Entity type', example: 'payment' })
  entityType: string;

  @ApiProperty({ description: 'Entity ID', example: 'pay_123' })
  entityId: string;

  @ApiProperty({ description: 'Reason code', example: 'duplicate' })
  reasonCode: string;

  @ApiProperty({ description: 'Refund status', example: 'completed' })
  refundStatus: string;
}

export class WebhookFeedDetailDto {
  @ApiProperty({ description: 'Webhook log ID', example: 'wh_log_123' })
  webhookLogId: string;

  @ApiProperty({ description: 'Event type', example: 'payment.received' })
  eventType: string;

  @ApiProperty({ description: 'Event ID', example: 'evt_123' })
  eventId: string;

  @ApiProperty({ description: 'Delivery status', example: 'success' })
  deliveryStatus: string;

  @ApiProperty({ description: 'Attempt count', example: 1 })
  attempts: number;

  @ApiPropertyOptional({ description: 'HTTP status code or null', nullable: true, example: 200 })
  httpStatus: number | null;

  @ApiPropertyOptional({ description: 'Last error or null', nullable: true, example: null })
  lastError: string | null;

  @ApiPropertyOptional({ description: 'Delivery timestamp or null', nullable: true, example: '2026-01-01T00:00:00.000Z' })
  deliveredAt: string | null;
}

export class NotificationFeedDetailDto {
  @ApiProperty({ description: 'Notification ID', example: 'notif_123' })
  notificationId: string;

  @ApiProperty({ description: 'Event type', example: 'payment.received' })
  eventType: string;

  @ApiProperty({ description: 'Event ID', example: 'evt_123' })
  eventId: string;

  @ApiProperty({ description: 'Notification title', example: 'Payment Received' })
  title: string;

  @ApiProperty({ description: 'Notification body', example: 'Received 10 USDC' })
  body: string;

  @ApiProperty({ description: 'Whether notification is read', example: false })
  read: boolean;
}

export class ContractFeedDetailDto {
  @ApiProperty({ description: 'Contract webhook ID', example: 'cwh_123' })
  contractWebhookId: string;

  @ApiProperty({ description: 'Webhook URL', example: 'https://example.com/webhook' })
  webhookUrl: string;

  @ApiProperty({ description: 'Whether webhook is enabled', example: true })
  enabled: boolean;
}

export class UsernameFeedDetailDto {
  @ApiProperty({ description: 'Username', example: 'alice' })
  username: string;

  @ApiProperty({ description: 'Stellar public key', example: 'GAA...' })
  publicKey: string;
}

export class FeedItemDto {
  @ApiProperty({ description: 'Feed entry identifier', example: 'feed_123' })
  id: string;

  @ApiProperty({
    description: 'Broad category of the event',
    enum: ['payment', 'refund', 'webhook_delivery', 'notification', 'contract_event', 'username_action'],
    example: 'payment',
  })
  kind: FeedItemKind;

  @ApiProperty({ description: 'ISO-8601 timestamp', example: '2026-01-01T00:00:00.000Z' })
  timestamp: string;

  @ApiProperty({ description: 'Title for the event', example: 'Payment Received' })
  title: string;

  @ApiPropertyOptional({ description: 'Additional description or null', nullable: true, example: 'Payment from user' })
  description: string | null;

  @ApiProperty({
    description: 'Outcome status',
    enum: ['success', 'pending', 'failed', 'cancelled', 'dlq', 'unread', 'read'],
    example: 'success',
  })
  status: FeedItemStatus;

  @ApiPropertyOptional({ description: 'Correlation ID or null', nullable: true, example: 'tx_abc123' })
  correlationId: string | null;

  @ApiPropertyOptional({ description: 'Payment detail or null', type: PaymentFeedDetailDto, nullable: true })
  paymentDetail: PaymentFeedDetailDto | null;

  @ApiPropertyOptional({ description: 'Refund detail or null', type: RefundFeedDetailDto, nullable: true })
  refundDetail: RefundFeedDetailDto | null;

  @ApiPropertyOptional({ description: 'Webhook detail or null', type: WebhookFeedDetailDto, nullable: true })
  webhookDetail: WebhookFeedDetailDto | null;

  @ApiPropertyOptional({ description: 'Notification detail or null', type: NotificationFeedDetailDto, nullable: true })
  notificationDetail: NotificationFeedDetailDto | null;

  @ApiPropertyOptional({ description: 'Contract detail or null', type: ContractFeedDetailDto, nullable: true })
  contractDetail: ContractFeedDetailDto | null;

  @ApiPropertyOptional({ description: 'Username detail or null', type: UsernameFeedDetailDto, nullable: true })
  usernameDetail: UsernameFeedDetailDto | null;
}

export class FeedPaginationDto {
  @ApiPropertyOptional({ description: 'Next cursor token or null', nullable: true, example: null })
  next_cursor: string | null;

  @ApiProperty({ description: 'Whether additional pages are available', example: false })
  has_more: boolean;

  @ApiProperty({ description: 'Page limit', example: 20 })
  limit: number;
}

export class FeedResponseDto {
  @ApiProperty({ type: [FeedItemDto], description: 'List of feed items' })
  data: FeedItemDto[];

  @ApiProperty({ type: FeedPaginationDto, description: 'Pagination details' })
  pagination: FeedPaginationDto;

  @ApiProperty({ description: 'Whether response contains partial data', example: false })
  isPartial: boolean;

  @ApiProperty({ description: 'Names of failed sources', type: [String], example: [] })
  failedSources: string[];
}
