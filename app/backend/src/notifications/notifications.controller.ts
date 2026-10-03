import { Body, Controller, Get, Param, Post, Query, Req } from "@nestjs/common";
import { ApiOkResponse, ApiOperation, ApiQuery, ApiTags } from "@nestjs/swagger";
import { Request } from "express";
import { InAppNotificationRepository } from "./in-app-notification.repository";
import { MarkManyReadDto } from "./dto/mark-many-read.dto";
import { InAppNotificationResponseDto } from "./dto/in-app-notification-response.dto";
import { RateLimitTier } from "../auth/decorators/rate-limit-group.decorator";

interface AuthenticatedRequest extends Request {
  user: { publicKey: string };
}

@ApiTags("notifications")
@Controller("notifications")
export class NotificationsController {
  constructor(private readonly inAppRepo: InAppNotificationRepository) {}

  @Get("in-app")
  @RateLimitTier("public-read")
  @ApiOperation({ summary: "Get in-app notifications for the authenticated user" })
  @ApiQuery({ name: "page", required: false, type: Number, example: 1 })
  @ApiQuery({ name: "limit", required: false, type: Number, example: 20 })
  @ApiOkResponse({
    description: "Array of in-app notifications",
    type: [InAppNotificationResponseDto],
  })
  async getInApp(
    @Req() req: AuthenticatedRequest,
    @Query("page") page = 1,
    @Query("limit") limit = 20,
  ): Promise<InAppNotificationResponseDto[]> {
    return this.inAppRepo.findByUser(req.user.publicKey, page, limit);
  }

  @Post("in-app/:id/read")
  @RateLimitTier("mutation")
  async markRead(@Req() req: AuthenticatedRequest, @Param("id") id: string) {
    await this.inAppRepo.markAsRead(req.user.publicKey, id);

    const unreadCount = await this.inAppRepo.getUnreadCount(req.user.publicKey);

    return {
      success: true,
      unreadCount,
      syncedAt: new Date().toISOString(),
    };
  }

  @Post("in-app/read")
  @RateLimitTier("mutation")
  async markManyRead(@Req() req: AuthenticatedRequest, @Body() body: MarkManyReadDto) {
    await this.inAppRepo.markManyAsRead(req.user.publicKey, body.ids);

    const unreadCount = await this.inAppRepo.getUnreadCount(req.user.publicKey);

    return {
      success: true,
      unreadCount,
      syncedAt: new Date().toISOString(),
    };
  }

  @Post("in-app/read-all")
  @RateLimitTier("mutation")
  async markAll(@Req() req: AuthenticatedRequest) {
    await this.inAppRepo.markAllAsRead(req.user.publicKey);

    const unreadCount = await this.inAppRepo.getUnreadCount(req.user.publicKey);

    return {
      success: true,
      unreadCount,
      syncedAt: new Date().toISOString(),
    };
  }
}
