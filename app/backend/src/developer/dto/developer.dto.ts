import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsArray,
  IsUUID,
  ArrayMinSize,
  ArrayMaxSize,
  IsBoolean,
  IsEnum,
  IsISO8601,
  IsOptional,
} from 'class-validator';

export const WEBHOOK_SAMPLE_EVENT_TYPES = [
  'link.created',
  'payment.received',
  'payment.settled',
  'payment.failed',
] as const;

export type WebhookSampleEventType = (typeof WEBHOOK_SAMPLE_EVENT_TYPES)[number];

export class WebhookSampleEventDto {
  @ApiPropertyOptional({
    enum: WEBHOOK_SAMPLE_EVENT_TYPES,
    default: 'payment.received',
    description: 'Canonical event type to send to the webhook receiver.',
  })
  @IsEnum(WEBHOOK_SAMPLE_EVENT_TYPES)
  @IsOptional()
  event_type?: WebhookSampleEventType;

  @ApiPropertyOptional({
    default: true,
    description: 'When false, omits QuickEx signature headers for receivers that are testing unsigned payloads.',
  })
  @IsBoolean()
  @IsOptional()
  include_signature?: boolean;

  @ApiPropertyOptional({
    example: '2026-04-29T12:00:00.000Z',
    description: 'Optional event timestamp. Defaults to the current server time.',
  })
  @IsISO8601()
  @IsOptional()
  timestamp?: string;
}

export class BulkRevokeDto {
  @ApiProperty({
    description: 'Array of API key UUIDs to revoke (max 100)',
    type: [String],
    example: ['3fa85f64-5717-4562-b3fc-2c963f66afa6'],
  })
  @IsArray()
  @ArrayMinSize(1)
  @ArrayMaxSize(100)
  @IsUUID('4', { each: true })
  ids: string[];
}

export class BulkRevokeFailedItemDto {
  @ApiProperty({ example: '3fa85f64-5717-4562-b3fc-2c963f66afa6' })
  id: string;

  @ApiProperty({ example: 'API key not found' })
  reason: string;
}

export class BulkRevokeResultDto {
  @ApiProperty({ type: [String], description: 'IDs successfully revoked' })
  revoked: string[];

  @ApiProperty({ type: [BulkRevokeFailedItemDto] })
  failed: BulkRevokeFailedItemDto[];

  @ApiProperty({ example: 5 })
  total: number;

  @ApiProperty({ example: 4 })
  success_count: number;

  @ApiProperty({ example: 1 })
  failure_count: number;
}

export class WebhookTestResultDto {
  @ApiProperty({ example: true })
  success: boolean;

  @ApiProperty({ example: '3fa85f64-5717-4562-b3fc-2c963f66afa6' })
  webhook_id: string;

  @ApiProperty({ example: 'https://example.com/webhooks' })
  target_url: string;

  @ApiPropertyOptional({ example: 200, nullable: true })
  http_status: number | null;

  @ApiPropertyOptional({ example: '{"ok":true}', nullable: true })
  response_body: string | null;

  @ApiProperty({ example: 142 })
  latency_ms: number;

  @ApiProperty({ example: '2026-04-29T12:00:00.000Z' })
  sent_at: string;

  @ApiPropertyOptional({ enum: WEBHOOK_SAMPLE_EVENT_TYPES, example: 'payment.received' })
  event_type?: WebhookSampleEventType;

  @ApiPropertyOptional({ example: 'evt_sample_123' })
  event_id?: string;

  @ApiPropertyOptional({ example: true })
  signature_included?: boolean;
}

export class HealthComponentsDto {
  @ApiProperty({ example: 0.05, description: '0–1 ratio of failed deliveries' })
  webhook_failure_rate: number;

  @ApiProperty({ example: 0.3, description: '0–1 ratio of quota consumed' })
  quota_utilization: number;

  @ApiProperty({ example: 57, description: 'Webhook reliability sub-score (0–60)' })
  webhook_score: number;

  @ApiProperty({ example: 40, description: 'Quota efficiency sub-score (0–40)' })
  quota_score: number;
}

export class IntegrationHealthDto {
  @ApiProperty({ example: 97, description: 'Composite score 0–100' })
  score: number;

  @ApiProperty({ enum: ['A', 'B', 'C', 'D', 'F'], example: 'A' })
  grade: 'A' | 'B' | 'C' | 'D' | 'F';

  @ApiProperty({ type: HealthComponentsDto })
  components: HealthComponentsDto;

  @ApiProperty({ example: '2026-04-29T12:00:00.000Z' })
  computed_at: string;
}

export class PingResponseDto {
  @ApiProperty({ example: 'ok' })
  status: 'ok';

  @ApiProperty({ example: '2026-04-29T12:00:00.000Z' })
  timestamp: string;

  @ApiProperty({ example: '0.1.0' })
  version: string;
}
