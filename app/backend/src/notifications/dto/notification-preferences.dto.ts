import {
  IsString,
  IsOptional,
  IsBoolean,
  IsEmail,
  IsUrl,
  IsArray,
  IsIn,
  IsNumber,
  Min,
} from "class-validator";
import { ApiProperty, ApiPropertyOptional } from "@nestjs/swagger";
import { Transform, Type } from "class-transformer";

import type {
  NotificationChannel,
  NotificationEventType,
} from "../types/notification.types";

const VALID_CHANNELS: NotificationChannel[] = ["email", "push", "webhook"];
const VALID_EVENTS: NotificationEventType[] = [
  "EscrowDeposited",
  "EscrowWithdrawn",
  "EscrowRefunded",
  "payment.received",
  "username.claimed",
];

export class UpsertNotificationPreferenceDto {
  @ApiProperty({ enum: VALID_CHANNELS, example: "email" })
  @IsIn(VALID_CHANNELS)
  channel!: NotificationChannel;

  @ApiPropertyOptional({ example: "user@example.com" })
  @IsOptional()
  @IsEmail()
  email?: string;

  @ApiPropertyOptional({ example: "ExponentPushToken[xxxx]" })
  @IsOptional()
  @IsString()
  pushToken?: string;

  @ApiPropertyOptional({ example: "https://example.com/hooks/quickex" })
  @IsOptional()
  @IsUrl()
  webhookUrl?: string;

  @ApiPropertyOptional({
    type: [String],
    enum: VALID_EVENTS,
    nullable: true,
    description:
      "null = all events; otherwise only listed event types trigger notifications",
    example: ["EscrowDeposited", "EscrowWithdrawn"],
  })
  @IsOptional()
  @IsArray()
  @IsIn(VALID_EVENTS, { each: true })
  events?: NotificationEventType[] | null;

  @ApiPropertyOptional({
    description:
      "Minimum amount in stroops (1 XLM = 10,000,000 stroops). 0 = no threshold.",
    example: 100000000,
  })
  @IsOptional()
  @IsNumber()
  @Min(0)
  @Type(() => Number)
  minAmountStroops?: number;

  @ApiPropertyOptional({ default: true })
  @IsOptional()
  @IsBoolean()
  @Transform(({ value }) => value ?? true)
  enabled?: boolean;
}

export class DisableChannelDto {
  @ApiProperty({ enum: VALID_CHANNELS })
  @IsIn(VALID_CHANNELS)
  channel!: NotificationChannel;
}

export class NotificationPreferenceResponseDto {
  @ApiProperty() id!: string;
  @ApiProperty() publicKey!: string;
  @ApiProperty({ enum: VALID_CHANNELS }) channel!: NotificationChannel;
  @ApiPropertyOptional() email?: string;
  @ApiPropertyOptional() pushToken?: string;
  @ApiPropertyOptional() webhookUrl?: string;
  @ApiPropertyOptional({ type: [String], nullable: true }) events!:
    | NotificationEventType[]
    | null;
  @ApiProperty({
    description: "Minimum amount in stroops as a string (bigint-safe)",
  })
  minAmountStroops!: string;
  @ApiProperty() enabled!: boolean;
}
