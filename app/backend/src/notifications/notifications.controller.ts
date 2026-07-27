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

@Controller('notifications')
export class NotificationsController {
  constructor(private readonly inAppRepo: InAppNotificationRepository) {}

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
