import { Body, Controller, Get, Param, Post, Query, Req } from "@nestjs/common";
import { InAppNotificationRepository } from "./in-app-notification.repository";
import { MarkManyReadDto } from "./dto/mark-many-read.dto";
import {
  BadRequestException,
  Controller,
  Get,
  Param,
  Post,
  Query,
  Req,
} from '@nestjs/common';
import { InAppNotificationRepository } from './in-app-notification.repository';

@Controller("notifications")
export class NotificationsController {
  constructor(private readonly inAppRepo: InAppNotificationRepository) {}

  @Get("in-app")
  getInApp(@Req() req, @Query("page") page = 1, @Query("limit") limit = 20) {
    return this.inAppRepo.findByUser(req.user.publicKey, page, limit);
  }

  @Post("in-app/:id/read")
  async markRead(@Req() req, @Param("id") id: string) {
    await this.inAppRepo.markAsRead(req.user.publicKey, id);

    const unreadCount = await this.inAppRepo.getUnreadCount(req.user.publicKey);

    return {
      success: true,
      unreadCount,
      syncedAt: new Date().toISOString(),
    };
  }

  @Post("in-app/read")
  async markManyRead(@Req() req, @Body() body: MarkManyReadDto) {
    await this.inAppRepo.markManyAsRead(req.user.publicKey, body.ids);

    const unreadCount = await this.inAppRepo.getUnreadCount(req.user.publicKey);

    return {
      success: true,
      unreadCount,
      syncedAt: new Date().toISOString(),
    };
  }

  @Post("in-app/read-all")
  async markAll(@Req() req) {
    await this.inAppRepo.markAllAsRead(req.user.publicKey);

    const unreadCount = await this.inAppRepo.getUnreadCount(req.user.publicKey);

    return {
      success: true,
      unreadCount,
      syncedAt: new Date().toISOString(),
    };
  private resolvePublicKey(
    req: { user?: { publicKey?: string } },
    queryPublicKey?: string,
  ): string {
    const publicKey = req.user?.publicKey ?? queryPublicKey;
    if (!publicKey) {
      throw new BadRequestException('publicKey is required');
    }
    return publicKey;
  }

  @Get('in-app')
  getInApp(
    @Req() req,
    @Query('page') page = 1,
    @Query('limit') limit = 20,
    @Query('publicKey') publicKey?: string,
  ) {
    return this.inAppRepo.findByUser(
      this.resolvePublicKey(req, publicKey),
      Number(page) || 1,
      Number(limit) || 20,
    );
  }

  @Post('in-app/:id/read')
  markRead(@Param('id') id: string) {
    return this.inAppRepo.markAsRead(id);
  }

  @Post('in-app/read-all')
  markAll(@Req() req, @Query('publicKey') publicKey?: string) {
    return this.inAppRepo.markAllAsRead(this.resolvePublicKey(req, publicKey));
  }
}
