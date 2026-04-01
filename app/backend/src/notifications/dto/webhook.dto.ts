import {
  IsString,
  IsOptional,
  IsUrl,
  IsArray,
  IsIn,
  IsNumber,
  Min,
  MaxLength,
} from "class-validator";
import { ApiProperty, ApiPropertyOptional } from "@nestjs/swagger";

import type { NotificationEventType } from "../types/notification.types";

const WEBHOOK_EVENTS: NotificationEventType[] = [
  "EscrowDeposited",
  "EscrowWithdrawn",
  "EscrowRefunded",
  "payment.received",
  "username.claimed",
  "recurring.payment.due",
  "recurring.payment.executed",
  "recurring.payment.failed",
  "recurring.payment.cancelled",
  "recurring.link.created",
  "recurring.link.updated",
  "recurring.link.paused",
  "recurring.link.resumed",
  "recurring.link.completed",
];

export class CreateWebhookDto {
  @ApiProperty({
    example: "https://example.com/webhooks/quickex",
    description: "URL to receive webhook POST requests",
  })
  @IsUrl(
    {
      protocols: ["http", "https"],
      require_tld: false, // Allow localhost for development
    },
    { message: "webhookUrl must be a valid URL" },
  )
  webhookUrl!: string;

  @ApiPropertyOptional({
    example: "my-webhook-1",
    maxLength: 100,
    description: "Optional label for this webhook",
  })
  @IsOptional()
  @IsString()
  @MaxLength(100)
  label?: string;

  @ApiPropertyOptional({
    type: [String],
    enum: WEBHOOK_EVENTS,
    nullable: true,
    description:
      "Event types to subscribe to. null = all events. Default: all payment events",
    example: ["payment.received", "EscrowDeposited"],
  })
  @IsOptional()
  @IsArray()
  @IsIn(WEBHOOK_EVENTS, { each: true })
  events?: NotificationEventType[] | null;

  @ApiPropertyOptional({
    description:
      "Minimum amount in stroops to trigger webhook (0 = no threshold)",
    example: 100000000, // 1 XLM
  })
  @IsOptional()
  @IsNumber()
  @Min(0)
  minAmountStroops?: number;

  @ApiPropertyOptional({
    example: "whsec_mysecretkey123",
    description:
      "Custom secret for signing payloads. If not provided, a secure secret will be generated.",
  })
  @IsOptional()
  @IsString()
  @MaxLength(128)
  secret?: string;
}

export class UpdateWebhookDto {
  @ApiPropertyOptional({
    example: "https://example.com/webhooks/quickex",
    description: "URL to receive webhook POST requests",
  })
  @IsOptional()
  @IsUrl(
    {
      protocols: ["http", "https"],
      require_tld: false,
    },
    { message: "webhookUrl must be a valid URL" },
  )
  webhookUrl?: string;

  @ApiPropertyOptional({
    example: "my-webhook-1",
    maxLength: 100,
    description: "Optional label for this webhook",
  })
  @IsOptional()
  @IsString()
  @MaxLength(100)
  label?: string;

  @ApiPropertyOptional({
    type: [String],
    enum: WEBHOOK_EVENTS,
    nullable: true,
    description: "Event types to subscribe to. null = all events.",
  })
  @IsOptional()
  @IsArray()
  @IsIn(WEBHOOK_EVENTS, { each: true })
  events?: NotificationEventType[] | null;

  @ApiPropertyOptional({
    description: "Minimum amount in stroops to trigger webhook",
  })
  @IsOptional()
  @IsNumber()
  @Min(0)
  minAmountStroops?: number;

  @ApiPropertyOptional({
    description: "Enable or disable this webhook",
  })
  @IsOptional()
  enabled?: boolean;
}

export class WebhookResponseDto {
  @ApiProperty() id!: string;
  @ApiProperty() publicKey!: string;
  @ApiProperty() webhookUrl!: string;
  @ApiPropertyOptional() label?: string;
  @ApiProperty({
    description: "Secret key for verifying webhook signatures",
    example: "whsec_xxxxxxxxxxxxxxxx",
  })
  secret!: string;
  @ApiPropertyOptional({ type: [String], nullable: true }) events!:
    | NotificationEventType[]
    | null;
  @ApiProperty() minAmountStroops!: string;
  @ApiProperty() enabled!: boolean;
  @ApiProperty() createdAt!: string;
  @ApiProperty() updatedAt!: string;
}

export class WebhookDeliveryLogDto {
  @ApiProperty() id!: string;
  @ApiProperty() eventType!: string;
  @ApiProperty() eventId!: string;
  @ApiProperty() status!: string;
  @ApiProperty() attempts!: number;
  @ApiPropertyOptional() lastError?: string;
  @ApiPropertyOptional() httpStatus?: number;
  @ApiPropertyOptional() responseBody?: string;
  @ApiProperty() createdAt!: string;
  @ApiPropertyOptional() deliveredAt?: string;
}

export class WebhookStatsDto {
  @ApiProperty() totalSent!: number;
  @ApiProperty() totalFailed!: number;
  @ApiProperty() pendingRetries!: number;
  @ApiPropertyOptional() lastDeliveryAt?: string;
  @ApiPropertyOptional() lastError?: string;
}
