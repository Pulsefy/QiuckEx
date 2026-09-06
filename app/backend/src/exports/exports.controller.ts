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
  HttpCode,
} from '@nestjs/common';
import { Response } from 'express';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { ApiKeyGuard } from '../auth/guards/api-key.guard';
import { RequestExportDto } from './dto/request-export.dto';
import { ExportStatusResponseDto } from './dto/export-status.dto';
import { ExportsService } from './exports.service';
import {
  ExportStorageService,
  EXPORT_LINK_INVALID,
  EXPORT_NOT_FOUND,
  type ArtifactRecord,
} from './export-storage.service';
import type { EnqueueExportResult } from './types/export.types';

@ApiTags('exports')
@UseGuards(ApiKeyGuard)
@Controller('exports')
export class ExportsController {
  private readonly logger = new Logger(ExportsController.name);

  constructor(
    private readonly exportsService: ExportsService,
    private readonly exportStorageService: ExportStorageService,
  ) {}

  @Post()
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Request a data export' })
  @ApiResponse({
    status: 201,
    description: 'Export job enqueued successfully',
    schema: {
      type: 'object',
      properties: {
        jobId: {
          type: 'string',
          description: 'Job ID for tracking the export',
        },
        status: { type: 'string', enum: ['queued'] },
        message: { type: 'string', description: 'Success message' },
      },
    },
  })
  @ApiResponse({ status: 400, description: 'Invalid request parameters' })
  async requestExport(
    @Body() dto: RequestExportDto,
  ): Promise<EnqueueExportResult> {
    return this.exportsService.requestExport(dto);
  }

  @Get(':jobId/download')
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
    const verification = this.exportStorageService.verifyDownloadToken({
      jobId,
      userId,
      token,
    });

    if (!verification.valid) {
      res.status(HttpStatus.BAD_REQUEST).json({
        statusCode: HttpStatus.BAD_REQUEST,
        errorCode: EXPORT_LINK_INVALID,
        message:
          'The download link is invalid, expired, or was not issued for this resource.',
      });
      return;
    }

    let artifact: ArtifactRecord | null;
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
        message:
          'Export artifact not found. It may have expired or been cleaned up.',
      });
      return;
    }

    if (artifact.userId !== userId) {
      res.status(HttpStatus.BAD_REQUEST).json({
        statusCode: HttpStatus.BAD_REQUEST,
        errorCode: EXPORT_LINK_INVALID,
        message:
          'The download link is invalid, expired, or was not issued for this resource.',
      });
      return;
    }

    let presignedUrl: string;
    try {
      presignedUrl = await this.exportStorageService.createPresignedDownloadUrl(
        artifact.storageKey,
      );
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      this.logger.error(
        `Failed to create presigned URL for job ${jobId}: ${msg}`,
      );
      res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({
        statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
        message: 'Failed to generate download URL.',
      });
      return;
    }

    this.logger.log(`Download link redeemed for job ${jobId} by user ${userId}`);
    res.redirect(HttpStatus.FOUND, presignedUrl);
  }

  @Get(':jobId')
  @ApiOperation({ summary: 'Get export job status' })
  @ApiResponse({
    status: 200,
    description: 'Current export status',
    type: ExportStatusResponseDto,
  })
  @ApiResponse({ status: 404, description: 'Export job not found' })
  async getExportStatus(
    @Param('jobId') jobId: string,
  ): Promise<ExportStatusResponseDto> {
    return this.exportsService.getStatus(jobId);
  }
}
