import { Controller, Post, Get, Body, UseGuards, Req } from '@nestjs/common';
import { Request } from 'express';
import { FeedbackService } from './feedback.service';
import { FeedbackDto } from './feedback.dto';
import { CustomThrottlerGuard } from '../auth/guards/custom-throttler.guard';
import { OrganizationRoleGuard } from '../auth/guards/organization-role.guard';

/**
 * Controller handling user feedback/report submissions.
 *
 * - POST /feedback : public endpoint for contributors to submit reports.
 * - GET  /feedback/admin : admin‑only endpoint to retrieve stored reports.
 */
@Controller('feedback')
export class FeedbackController {
  constructor(private readonly feedbackService: FeedbackService) {}

  @Post()
  @UseGuards(CustomThrottlerGuard) // anti‑abuse rate limiting
  async submit(@Body() feedback: FeedbackDto, @Req() req: Request) {
    // The service will handle redaction of sensitive fields.
    const stored = await this.feedbackService.createFeedback(feedback, req.ip);
    return { message: 'Feedback submitted', id: stored.id };
  }

  @Get('admin')
  @UseGuards(OrganizationRoleGuard) // admin guard (placeholder)
  async adminList() {
    return await this.feedbackService.listAll();
  }
}
