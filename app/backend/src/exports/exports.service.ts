import { BadRequestException, Injectable, NotFoundException } from '@nestjs/common';
import { JobQueueService } from '../job-queue/job-queue.service';
import { ExportGenerationPayload } from '../job-queue/types/job-payloads.types';
import { JobStatus, JobType } from '../job-queue/types';
import { RequestExportDto } from './dto/request-export.dto';
import { ExportStatusDto } from './dto/export-status.dto';

const EXPORT_TYPES = ['transactions', 'links', 'payments'] as const;
const EXPORT_FORMATS = ['csv', 'json'] as const;
const DELIVERY_METHODS = ['webhook', 'email', 'download'] as const;

@Injectable()
export class ExportsService {
  constructor(private readonly jobQueueService: JobQueueService) {}

  async requestExport(dto: RequestExportDto): Promise<{ jobId: string; message: string }> {
    this.validateRequest(dto);

    const payload: ExportGenerationPayload = {
      userId: dto.userId.trim(),
      exportType: dto.exportType,
      filters: dto.filters ?? {},
      format: dto.format,
      deliveryMethod: dto.deliveryMethod,
    };
    const jobId = await this.jobQueueService.enqueue(JobType.EXPORT_GENERATION, payload);

    return {
      jobId,
      message: `Export job enqueued successfully. Job ID: ${jobId}`,
    };
  }

  async getStatus(jobId: string): Promise<ExportStatusDto> {
    const job = await this.jobQueueService.getJob<ExportGenerationPayload>(jobId);
    if (!job || job.type !== JobType.EXPORT_GENERATION) {
      throw new NotFoundException(`Export ${jobId} not found`);
    }

    const status = job.status === JobStatus.PENDING
      ? 'queued'
      : job.status === JobStatus.CANCELLED
        ? 'failed'
        : job.status;

    return {
      exportId: job.id,
      status,
      createdAt: job.createdAt.toISOString(),
      startedAt: job.startedAt?.toISOString() ?? null,
      completedAt: job.completedAt?.toISOString() ?? null,
      ...(job.status === JobStatus.COMPLETED ? { deliveryReference: job.id } : {}),
      ...(job.failureReason ? { failureReason: job.failureReason } : {}),
    };
  }

  private validateRequest(dto: RequestExportDto): void {
    if (!dto || typeof dto.userId !== 'string' || dto.userId.trim().length === 0) {
      throw new BadRequestException('userId is required and must be a non-empty string');
    }
    if (!EXPORT_TYPES.includes(dto.exportType)) {
      throw new BadRequestException('exportType must be one of: transactions, links, payments');
    }
    if (!EXPORT_FORMATS.includes(dto.format)) {
      throw new BadRequestException('format must be one of: csv, json');
    }
    if (!DELIVERY_METHODS.includes(dto.deliveryMethod)) {
      throw new BadRequestException('deliveryMethod must be one of: webhook, email, download');
    }
    if (dto.filters !== undefined && !this.isFilterRecord(dto.filters)) {
      throw new BadRequestException('filters must be an object containing scalar values');
    }
  }

  private isFilterRecord(value: unknown): value is Record<string, unknown> {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) {
      return false;
    }

    return Object.entries(value).every(([key, filterValue]) =>
      key.trim().length > 0 &&
      (filterValue === null ||
        typeof filterValue === 'string' ||
        typeof filterValue === 'boolean' ||
        (typeof filterValue === 'number' && Number.isFinite(filterValue))),
    );
  }
}