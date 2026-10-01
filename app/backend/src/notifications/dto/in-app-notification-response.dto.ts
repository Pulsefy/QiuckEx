import { ApiProperty, ApiPropertyOptional } from "@nestjs/swagger";
import { InAppNotification } from "../entities/in-app-notification.entity";
import { NotificationEventType } from "../types/notification.types";

const NOTIFICATION_EVENT_TYPES: NotificationEventType[] = [
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
  "auto_reconciliation.succeeded",
  "payment.link.expired",
  "export.completed",
  "export.failed",
];

export class InAppNotificationResponseDto implements InAppNotification {
  @ApiProperty({ example: "2d2ef5a1-87f7-42f8-9b6c-85f5b5ec7d19" })
  id!: string;

  @ApiProperty({ example: "GTEST123..." })
  publicKey!: string;

  @ApiProperty({ enum: NOTIFICATION_EVENT_TYPES })
  eventType!: NotificationEventType;

  @ApiProperty({ example: "evt_123" })
  eventId!: string;

  @ApiProperty({ example: "Payment Received" })
  title!: string;

  @ApiProperty({ example: "You received 100 XLM from GABCD..." })
  body!: string;

  @ApiProperty({ example: false })
  read!: boolean;

  @ApiPropertyOptional({ example: { amount: "100", asset: "XLM" } })
  metadata?: Record<string, unknown>;

  @ApiProperty({ example: "2026-09-27T17:18:50Z" })
  createdAt!: string;
}