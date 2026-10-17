import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  InternalServerErrorException,
  NotFoundException,
} from '@nestjs/common';
import { JobQueueService } from '../job-queue/job-queue.service';
import { ExportGenerationPayload } from '../job-queue/types/job-payloads.types';
import { JobStatus, JobType } from '../job-queue/types';
import { NotificationPreferencesRepository } from '../notifications/notification-preferences.repository';
import { isDeliverableWebhookUrl } from '../notifications/webhook-target.util';
import type { NotificationPreference } from '../notifications/types/notification.types';
import { RequestExportDto } from './dto/request-export.dto';
import { ExportStatusDto } from './dto/export-status.dto';

const EXPORT_TYPES = ['transactions', 'links', 'payments'] as const;
const EXPORT_FORMATS = ['csv', 'json'] as const;
const DELIVERY_METHODS = ['webhook', 'email', 'download'] as const;

/**
 * Error code returned when webhook delivery is requested but the caller has no
 * usable webhook target registered.
 */
export const EXPORT_WEBHOOK_TARGET_MISSING = 'EXPORT_WEBHOOK_TARGET_MISSING';

export interface ExportRequester {
  owner_id?: string | null;
  organization_id?: string | null;
}

@Injectable()
export class ExportsService {
  constructor(
    private readonly jobQueueService: JobQueueService,
    private readonly notificationPrefsRepo: NotificationPreferencesRepository,
  ) {}

  async requestExport(
    dto: RequestExportDto,
    requester: ExportRequester,
  ): Promise<{ jobId: string; message: string }> {
    this.validateRequest(dto);

    const userId = dto.userId.trim();
    this.assertCanAccessUser(userId, requester);

    // Fail fast at the API boundary rather than inside the background handler:
    // a webhook export with no registered target can never be delivered, and
    // reporting it as an accepted job only fails silently much later.
    if (dto.deliveryMethod === 'webhook') {
      await this.assertWebhookTargetAvailable(userId);
    }

    const payload: ExportGenerationPayload = {
      userId,
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

  async getStatus(jobId: string, requester: ExportRequester): Promise<ExportStatusDto> {
    const job = await this.jobQueueService.getJob<ExportGenerationPayload>(jobId);
    if (!job || job.type !== JobType.EXPORT_GENERATION) {
      throw new NotFoundException(`Export ${jobId} not found`);
    }
    this.assertCanAccessUser(job.payload.userId, requester);

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

  private assertCanAccessUser(userId: string, requester: ExportRequester): void {
    if (requester.owner_id !== userId && requester.organization_id !== userId) {
      throw new ForbiddenException('API key does not have access to this user exports');
    }
  }

  /**
   * Only absolute https URLs are accepted as webhook targets: http would leak
   * the signed download reference in transit, and a relative/garbage value
   * cannot be delivered to at all. Shares its predicate with
   * `ExportGenerationHandler` so request-time and delivery-time validation
   * cannot drift apart.
   *
   * @throws BadRequestException with code EXPORT_WEBHOOK_TARGET_MISSING
   */
  private async assertWebhookTargetAvailable(userId: string): Promise<void> {
    let preferences: NotificationPreference[];
    try {
      preferences = await this.notificationPrefsRepo.getWebhooksByPublicKey(userId);
    } catch (error) {
      // A lookup failure is a server problem, not a client one — surface it
      // as-is rather than misleading the caller about their webhook config.
      throw new InternalServerErrorException(
        `Unable to verify webhook delivery target for user ${userId}: ${
          error instanceof Error ? error.message : 'unknown error'
        }`,
      );
    }

    const target = preferences?.find(
      (preference) =>
        preference.enabled && isDeliverableWebhookUrl(preference.webhookUrl),
    );

    if (!target) {
      throw new BadRequestException({
        code: EXPORT_WEBHOOK_TARGET_MISSING,
        message:
          'deliveryMethod "webhook" requires an enabled webhook target with a valid https URL. ' +
          'Register one before requesting the export.',
      });
    }
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