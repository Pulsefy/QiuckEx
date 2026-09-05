/*
 * Exports Controller
 *
 * Provides endpoints for requesting data exports and redeeming signed download
 * links (BE-102).
 *
 * Requirements: 9.2, BE-102
 */

import {
  Controller,
  Post,
  Get,
  Body,
  Param,
  Query,
  UseGuards,
  Logger,
  Res,
  HttpStatus,
} from '@nestjs/common';
import { Response } from 'express';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { ApiKeyGuard } from '../auth/guards/api-key.guard';
import { RateLimitGroup } from '../auth/decorators/rate-limit-group.decorator';
import { JobQueueService } from '../job-queue/job-queue.service';
import { JobType } from '../job-queue/types';
import { ExportGenerationPayload } from '../job-queue/types/job-payloads.types';
import { RequestExportDto } from './dto/request-export.dto';
import {
  ExportStorageService,
  EXPORT_LINK_INVALID,
  EXPORT_NOT_FOUND,
 } from './export-storage.service';


/**
 * Exports Controller
 *
 * POST /exports          - enqueue an export job.
 * GET  /exports/:jobId/download - redeem a signed download token.
 */
@ApiTags('exports')
@UseGuards(ApiKeyGuard)
@Controller('exports')
export class ExportsController {
  private readonly logger = new Logger(ExportsController.name);

  constructor(
    private readonly jobQueueService: JobQueueService,
    private readonly exportStorageService: ExportStorageService,
  ) {}

  /**
   * Request a data export
   *
   * Enqueues an export_generation job to process the export asynchronously.
   * The export will be delivered via the specified deliveryMethod.
   */
  @Post()
  @RateLimitGroup('export')
  @ApiOperation({ summary: 'Request a data export' })
  @ApiResponse({
    status: 201,
    description: 'Export job enqueued successfully',
    schema: {
      type: 'object',
      properties: {
        jobId: { type: 'string', description: 'Job ID for tracking the export' },
        message: { type: 'string', description: 'Success message' },
      },
    },
  })
  @ApiResponse({ status: 400, description: 'Invalid request parameters' })
  async requestExport(
    @Body() dto: RequestExportDto,
  ): Promise<{ jobId: string; message: string }> {
    this.logger.log(
      `Export requested: userId=${dto.userId}, type=${dto.exportType}, format=${dto.format}, delivery=${dto.deliveryMethod}`,
    );

    const payload: ExportGenerationPayload = {
      userId: dto.userId,
      exportType: dto.exportType,
      filters: dto.filters || {},
      format: dto.format,
      deliveryMethod: dto.deliveryMethod,
    };

    const jobId = await this.jobQueueService.enqueue(
      JobType.EXPORT_GENERATION,
      payload,
    );

    this.logger.log(`Export job enqueued: ${jobId}`);

    return {
      jobId,
      message: `Export job enqueued successfully. Job ID: ${jobId}`,
    };
  }

  /**
   * Redeem a signed export download link.
   *
   * Query parameters:
   *   - userId  : the principal who requested the export (scopes the token)
   *   - token   : the HMAC-signed token issued by ExportStorageService
   *
   * On success: 302 redirect to a short-lived presigned Supabase Storage URL.
   * On failure: 400 with stable error code EXPORT_LINK_INVALID or
   *             404 with EXPORT_NOT_FOUND.
   *
   * Expiry and tampering are both rejected with EXPORT_LINK_INVALID so that
   * callers do not receive signal about which condition triggered the rejection.
   */
  @Get(':jobId/download')
  @RateLimitGroup('download')
  @ApiOperation({ summary: 'Redeem a signed export download link' })
  @ApiResponse({ status: 302, description: 'Redirect to presigned download URL' })
  @ApiResponse({ status: 400, description: 'Token invalid, expired, or tampered' })
  @ApiResponse({ status: 404, description: 'Artifact not found' })
  async redeemDownloadLink(
    @Param('jobId') jobId: string,
    @Query('userId') userId: string,
    @Query('token') token: string,
    @Res() res: Response,
  ): Promise<void> {
    // 1. Verify the download token (handles expiry + tampering + principal mismatch)
    const verification = this.exportStorageService.verifyDownloadToken({
      jobId,
      userId,
      token,
    });

    if (!verification.valid) {
      res.status(HttpStatus.BAD_REQUEST).json({
        statusCode: HttpStatus.BAD_REQUEST,
        errorCode: EXPORT_LINK_INVALID,
        message: 'The download link is invalid, expired, or was not issued for this resource.',
      });
      return;
    }

    // 2. Look up the artifact record to get the storage key
    let artifact: { userId: string; storageKey: string } | null = null;
    try {
      artifact = await this.exportStorageService.findArtifactRecord(jobId);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      this.logger.error(`Artifact lookup failed for job ${jobId}: ${msg}`);
      res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({
        statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
        message: 'Failed to retrieve artifact metadata.',
      });
      return;
    }

    if (!artifact) {
      res.status(HttpStatus.NOT_FOUND).json({
        statusCode: HttpStatus.NOT_FOUND,
        errorCode: EXPORT_NOT_FOUND,
        message: 'Export artifact not found. It may have expired or been cleaned up.',
      });
      return;
    }

    // 3. Double-check ownership at the record level (defence-in-depth)
    if (artifact.userId !== userId) {
      // Return the same stable code as an invalid token to avoid oracle attacks
      res.status(HttpStatus.BAD_REQUEST).json({
        statusCode: HttpStatus.BAD_REQUEST,
        errorCode: EXPORT_LINK_INVALID,
        message: 'The download link is invalid, expired, or was not issued for this resource.',
      });
      return;
    }

    // 4. Generate a short-lived presigned URL and redirect the client
    let presignedUrl: string;
    try {
      presignedUrl = await this.exportStorageService.createPresignedDownloadUrl(
        artifact.storageKey,
      );
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      this.logger.error(`Failed to create presigned URL for job ${jobId}: ${msg}`);
      res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({
        statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
        message: 'Failed to generate download URL.',
      });
      return;
    }

    this.logger.log(`Download link redeemed for job ${jobId} by user ${userId}`);
    res.redirect(HttpStatus.FOUND, presignedUrl);
  }
}
