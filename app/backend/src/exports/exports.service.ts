import {
  BadRequestException,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { JobQueueService, PayloadValidationError } from '../job-queue/job-queue.service';
import { JobType } from '../job-queue/types';
import type { ExportGenerationPayload } from '../job-queue/types/job-payloads.types';
import { EXPORT_ENQUEUED_MESSAGE } from './constants/export.constants';
import { ExportStatus } from './enums/export.enums';
import type { RequestExportDto } from './dto/request-export.dto';
import { ExportRepository } from './export.repository';
import type {
  EnqueueExportResult,
  ExportRecord,
  ExportStatusView,
} from './types/export.types';
import { toExportStatusView } from './utils/export-status.util';
import {
  collectExportValidationErrors,
  normalizeExportFilters,
} from './utils/export-validation.util';

@Injectable()
export class ExportsService {
  private readonly logger = new Logger(ExportsService.name);

  constructor(
    private readonly jobQueueService: JobQueueService,
    private readonly exportRepository: ExportRepository,
  ) {}

  async requestExport(dto: RequestExportDto): Promise<EnqueueExportResult> {
    this.assertValidRequest(dto);

    const filters = normalizeExportFilters(dto.filters);
    const payload: ExportGenerationPayload = {
      userId: dto.userId,
      exportType: dto.exportType,
      filters,
      format: dto.format,
      deliveryMethod: dto.deliveryMethod,
    };

    let jobId: string;

    try {
      jobId = await this.jobQueueService.enqueue(
        JobType.EXPORT_GENERATION,
        payload,
      );
    } catch (error) {
      if (error instanceof PayloadValidationError) {
        throw new BadRequestException(error.message);
      }
      throw error;
    }

    try {
      await this.exportRepository.create({
        jobId,
        userId: dto.userId,
        exportType: dto.exportType,
        format: dto.format,
        deliveryMethod: dto.deliveryMethod,
        filters,
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.logger.error(
        `Failed to persist export record for job ${jobId}: ${message}`,
      );

      try {
        await this.jobQueueService.cancel(jobId);
      } catch (cancelError) {
        const cancelMessage =
          cancelError instanceof Error ? cancelError.message : String(cancelError);
        this.logger.error(
          `Failed to cancel export job ${jobId} after persist failure: ${cancelMessage}`,
        );
      }

      throw error;
    }

    this.logger.log(
      `Export enqueued: jobId=${jobId} userId=${dto.userId} type=${dto.exportType}`,
    );

    return {
      jobId,
      status: ExportStatus.QUEUED,
      message: `${EXPORT_ENQUEUED_MESSAGE}. Job ID: ${jobId}`,
    };
  }

  async getStatus(jobId: string): Promise<ExportStatusView> {
    const record = await this.exportRepository.findByJobId(jobId);

    if (!record) {
      throw new NotFoundException(`Export job not found: ${jobId}`);
    }

    return toExportStatusView(record);
  }

  async markRunning(jobId: string): Promise<ExportRecord> {
    return this.exportRepository.transition(jobId, ExportStatus.RUNNING);
  }

  async markCompleted(
    jobId: string,
    deliveryReference: string,
  ): Promise<ExportRecord> {
    return this.exportRepository.transition(jobId, ExportStatus.COMPLETED, {
      deliveryReference,
    });
  }

  async markFailed(jobId: string, failureReason: string): Promise<ExportRecord> {
    return this.exportRepository.transition(jobId, ExportStatus.FAILED, {
      failureReason,
    });
  }

  private assertValidRequest(dto: RequestExportDto): void {
    const errors = collectExportValidationErrors(dto);

    if (errors.length > 0) {
      throw new BadRequestException(
        `Invalid export request: ${errors.join(', ')}`,
      );
    }
  }
}
