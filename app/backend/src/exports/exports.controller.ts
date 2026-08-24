/**
 * Exports Controller
 * 
 * Provides endpoints for requesting data exports.
 * Exports are processed asynchronously via the job queue system.
 * 
 * Requirements: 9.2
 */

import { Controller, Post, Get, Body, Query, Req, Res, UseGuards, Logger } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { Response, Request } from 'express';
import { ApiKeyGuard } from '../auth/guards/api-key.guard';
import { JobQueueService } from '../job-queue/job-queue.service';
import { JobType } from '../job-queue/types';
import { ExportGenerationPayload } from '../job-queue/types/job-payloads.types';
import { RequestExportDto } from './dto/request-export.dto';
import { ExportsService } from './exports.service';

/**
 * Exports Controller
 * 
 * Handles export requests by enqueuing export_generation jobs.
 * Exports are processed asynchronously and delivered via the specified method.
 */
@ApiTags('exports')
@UseGuards(ApiKeyGuard)
@Controller('exports')
export class ExportsController {
  private readonly logger = new Logger(ExportsController.name);

  constructor(
    private readonly jobQueueService: JobQueueService,
    private readonly exportsService: ExportsService,
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

  /**
   * Download a generated export file
   * 
   * Validates URL signature, expiration, and checks requesting principal match.
   */
  @Get('download')
  @ApiOperation({ summary: 'Download a data export file' })
  @ApiResponse({
    status: 200,
    description: 'Export file download started',
  })
  @ApiResponse({
    status: 400,
    description: 'Expired or invalid/tampered signature',
  })
  @ApiResponse({
    status: 403,
    description: 'Unauthorized access (mismatched requesting principal)',
  })
  @ApiResponse({
    status: 404,
    description: 'Export file not found in storage',
  })
  async downloadExport(
    @Query('userId') userId: string,
    @Query('jobId') jobId: string,
    @Query('format') format: 'csv' | 'json',
    @Query('expiresAt') expiresAt: string,
    @Query('signature') signature: string,
    @Req() req: Request & { apiKey?: { owner_id?: string; organization_id?: string; id?: string } },
    @Res() res: Response,
  ): Promise<void> {
    this.logger.log(`Export download requested: userId=${userId}, jobId=${jobId}`);

    const requestingPrincipal = req.apiKey?.owner_id || req.apiKey?.organization_id || req.apiKey?.id;

    const { data, contentType } = await this.exportsService.verifyAndRetrieveArtifact(
      { userId, jobId, format, expiresAt, signature },
      requestingPrincipal,
    );

    res.setHeader('Content-Type', contentType);
    res.setHeader('Content-Disposition', `attachment; filename="export-${jobId}.${format}"`);
    res.send(data);
  }
}
