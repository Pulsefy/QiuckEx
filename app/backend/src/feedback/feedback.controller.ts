import { Controller, Post, Get, Body, UseGuards, Req } from '@nestjs/common';
import { ApiCreatedResponse, ApiOkResponse, ApiOperation, ApiTags } from '@nestjs/swagger';
import { Request } from 'express';
import { FeedbackService } from './feedback.service';
import { CreateFeedbackResponseDto, FeedbackDto, StoredFeedbackDto } from './feedback.dto';
import { CustomThrottlerGuard } from '../auth/guards/custom-throttler.guard';
import { OrganizationRoleGuard } from '../auth/guards/organization-role.guard';

/**
 * Controller handling user feedback/report submissions.
 *
 * - POST /feedback : public endpoint for contributors to submit reports.
 * - GET  /feedback/admin : admin‑only endpoint to retrieve stored reports.
 */
@ApiTags('feedback')
@Controller('feedback')
export class FeedbackController {
  constructor(private readonly feedbackService: FeedbackService) {}

  @Post()
  @UseGuards(CustomThrottlerGuard) // anti‑abuse rate limiting
  @ApiOperation({ summary: 'Submit user feedback or bug report' })
  @ApiCreatedResponse({
    description: 'Feedback successfully submitted',
    type: CreateFeedbackResponseDto,
  })
  async submit(@Body() feedback: FeedbackDto, @Req() req: Request): Promise<CreateFeedbackResponseDto> {
    // The service will handle redaction of sensitive fields.
    const stored = await this.feedbackService.createFeedback(feedback, req.ip);
    return { message: 'Feedback submitted', id: stored.id };
  }

  @Get('admin')
  @UseGuards(OrganizationRoleGuard) // admin guard (placeholder)
  @ApiOperation({ summary: 'List all submitted feedback reports (admin only)' })
  @ApiOkResponse({
    description: 'List of stored feedback reports',
    type: [StoredFeedbackDto],
  })
  async adminList(): Promise<StoredFeedbackDto[]> {
    return await this.feedbackService.listAll();
  }
}

