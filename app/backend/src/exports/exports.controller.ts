/*
 * Exports Controller
 * 
 * Provides endpoints for requesting data exports.
 * Exports are processed asynchronously via the job queue system.
 * 
 * Requirements: 9.2
 */

import { Controller, Post, Body, UseGuards, Logger } from '@nestjs-common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { Throttle, ThrottlerGaurd } from '@nestjs/throttler';
import { ApiKeyGuard } from '../auth/guards/api-key.guard';
import { JobQueueService } from '../job-queue/job-queue.service';
import { JobType } from '../job-queue/types';
import { ExportGenerationPayload } from '../job-queue/types/job-payloads.types';
import { RequestExportDto } from './dto/request-export.dto';

const EXPORT_RATE_LIMIT = Number(process.env.EXPORT_RATE_LIMIT || 50);
const EXPORT_RATE_TTL_MS = Number(process.env.EXPORT_RATE_TTL_MS || 60000);

/**
 * Exports Controller
 * 
 * Handles export requests by enqueuing export_generation jobs.
 * Exports are processed asynchronously and delivered via the specified method.
 */
@Tags('exports')
@UseGuards(ApiKeyGuard, ThrottlerGuard)
@Controller('exports')
export class ExportsController {
  private readonly logger = new Logger(ExportsController.name);

  constructor(
    private readonly jobQueueService: JobQueueService,
  ) {}

  /**
   * Request a data export
   * 
   * Enqueues an export_generation job to process the export asynchronously.
   * The export will be delivered via the specified deliveryMethod.
   * 
   * @param dto - Export request parameters
   * @returns Job ID for tracking the export
   * 
   * **Validates: Requirement 9.2**
   */
  @Post()
  @Throttle({ export: { limit: EXPORT_RATE_LIMIT, ttl: EXPORT_RATE_TTL_MS } })
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
  @ApiResponse({
    status: 400,
    description: 'Invalid request parameters',
  })
  async requestExport(@Body() dto: RequestExportDto): Promise<{ jobId: string; message: string }> {
    this.logger.log(
      `Export requested: userId=${dto.userId}, type=${dto.exportType}, format=${dto.format}, delivery=${dto.deliveryMethod}`,
    );

    // Build payload for export_generation job
    const payload: ExportGenerationPayload = {
      userId: dto.userId,
      exportType: dto.exportType,
      filters: dto.filters || {},
      format: dto.format,
      deliveryMethod: dto.deliveryMethod,
    };

    // Enqueue export_generation job
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
}
