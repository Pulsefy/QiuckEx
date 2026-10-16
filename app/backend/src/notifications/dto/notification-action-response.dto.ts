import { ApiProperty } from "@nestjs/swagger";

export class NotificationActionResponseDto {
  @ApiProperty({ description: "Success status", example: true })
  success: boolean;

  @ApiProperty({ description: "Remaining unread notifications count", example: 0 })
  unreadCount: number;

  @ApiProperty({ description: "ISO timestamp when action was synced", example: "2026-01-01T00:00:00.000Z" })
  syncedAt: string;
}
