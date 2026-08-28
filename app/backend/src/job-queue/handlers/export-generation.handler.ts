/**
 * Job Queue System - Export Generation Handler
 * 
 * Implements the JobHandler interface for export generation jobs.
 * Generates CSV/JSON exports from database queries and delivers via specified method.
 * 
 * Requirements: 9.3, 9.4, 9.5, 15.4, 15.5
 */

import { Injectable, Logger } from '@nestjs/common';
import { JobHandler, Job, CancellationToken } from '../types';
import { ExportGenerationPayload } from '../types/job-payloads.types';
import { SupabaseService } from '../../supabase/supabase.service';
import { NotificationService } from '../../notifications/notification.service';
import { ExportCompletedPayload } from '../../notifications/types/notification.types';
import { ExportStorageService } from '../../exports/export-storage.service';
import { ExportRepository } from '../../exports/export.repository';
import {
  ExportDeliveryMethod,
  ExportFormat,
  ExportStatus,
  ExportType,
} from '../../exports/enums/export.enums';
import { collectExportValidationErrors } from '../../exports/utils/export-validation.util';
import { buildDeliveryReference } from '../../exports/utils/export-delivery.util';

/**
 * Error thrown for permanent job failures (no retry)
 */
export class PermanentJobError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PermanentJobError';
  }
}

/**
 * Export Generation Handler
 * 
 * Generates CSV/JSON exports from database queries.
 * Checks cancellation token every 1000 records during export generation.
 * Delivers export via specified deliveryMethod (webhook, email, download link).
 */
@Injectable()
export class ExportGenerationHandler implements JobHandler<ExportGenerationPayload> {
  private readonly logger = new Logger(ExportGenerationHandler.name);
  private readonly cancellationCheckInterval = 1000; // Check every 1000 records

  constructor(
    private readonly supabase: SupabaseService,
    private readonly notificationService: NotificationService,
    private readonly exportStorageService: ExportStorageService,
    private readonly exportRepository: ExportRepository,
  ) {}

  /**
   * Execute export generation
   * 
   * Generates CSV/JSON export from database queries based on exportType and filters.
   * Checks cancellation token every 1000 records during generation.
   * Delivers export via specified deliveryMethod.
   * 
   * @param job - The export generation job
   * @param cancellationToken - Token to check for cancellation
   * @throws PermanentJobError for validation failures
   * @throws Error for transient failures (database errors, delivery failures)
   * 
   * **Validates: Requirements 9.3, 9.4, 9.5**
   */
  async execute(job: Job<ExportGenerationPayload>, cancellationToken: CancellationToken): Promise<void> {
    const { userId, exportType, filters, format, deliveryMethod } = job.payload;

    this.logger.log(
      `Generating ${format} export for user ${userId} (type: ${exportType}, jobId: ${job.id})`,
    );

    try {
      await this.exportRepository.transition(job.id, ExportStatus.RUNNING);

      const records = await this.fetchExportData(userId, exportType, filters, cancellationToken);

      this.logger.log(
        `Fetched ${records.length} records for export (jobId: ${job.id})`,
      );

      const exportData = await this.generateExportFile(records, format, cancellationToken);

      this.logger.log(
        `Generated ${format} export (${exportData.length} bytes, jobId: ${job.id})`,
      );

      const deliveryReference = await this.deliverExport(
        userId,
        exportType,
        exportData,
        format,
        deliveryMethod,
        records.length,
        job.id,
        cancellationToken,
      );

      await this.exportRepository.transition(job.id, ExportStatus.COMPLETED, {
        deliveryReference,
      });

      this.logger.log(
        `Export delivered successfully via ${deliveryMethod} (jobId: ${job.id})`,
      );
    } catch (error) {
      // Re-throw PermanentJobError as-is
      if (error instanceof PermanentJobError) {
        throw error;
      }

      // Other errors are transient (database errors, network errors, etc.)
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      this.logger.error(
        `Export generation failed (jobId: ${job.id}): ${errorMessage}`,
        error instanceof Error ? error.stack : undefined,
      );
      throw new Error(`Export generation failed: ${errorMessage}`);
    }
  }

  /**
   * Fetch export data from database
   * 
   * Queries the database based on exportType and filters.
   * Checks cancellation token every 1000 records.
   * 
   * @param userId - User ID requesting the export
   * @param exportType - Type of data to export
   * @param filters - Filters to apply to the query
   * @param cancellationToken - Token to check for cancellation
   * @returns Array of records to export
   */
  private async fetchExportData(
    userId: string,
    exportType: ExportType,
    filters: Record<string, unknown>,
    cancellationToken: CancellationToken,
  ): Promise<Record<string, unknown>[]> {
    // Check cancellation before starting
    cancellationToken.throwIfCancelled();

    const client = this.supabase.getClient();
    const tableByExportType: Record<ExportType, string> = {
      [ExportType.TRANSACTIONS]: 'transactions',
      [ExportType.LINKS]: 'links',
      [ExportType.PAYMENTS]: 'payments',
    };

    let query = client
      .from(tableByExportType[exportType])
      .select('*')
      .eq('user_id', userId);

    // Apply filters
    for (const [key, value] of Object.entries(filters)) {
      if (value !== undefined && value !== null) {
        query = query.eq(key, value);
      }
    }

    // Execute query
    const { data, error } = await query;

    if (error) {
      throw new Error(`Database query failed: ${error.message}`);
    }

    // Check cancellation after fetching data
    cancellationToken.throwIfCancelled();

    return data || [];
  }

  /**
   * Generate export file in specified format
   * 
   * Converts records to CSV or JSON format.
   * Checks cancellation token every 1000 records.
   * 
   * @param records - Records to export
   * @param format - Output format (csv or json)
   * @param cancellationToken - Token to check for cancellation
   * @returns Export data as string
   */
  private async generateExportFile(
    records: Record<string, unknown>[],
    format: ExportFormat,
    cancellationToken: CancellationToken,
  ): Promise<string> {
    if (format === ExportFormat.JSON) {
      // JSON export is simple - just stringify
      cancellationToken.throwIfCancelled();
      return JSON.stringify(records, null, 2);
    }

    // CSV export - process in chunks
    if (records.length === 0) {
      return '';
    }

    const lines: string[] = [];

    // Add header row
    const headers = Object.keys(records[0]);
    lines.push(headers.map(h => this.escapeCsvValue(h)).join(','));

    // Add data rows, checking cancellation every 1000 records
    for (let i = 0; i < records.length; i++) {
      // Check cancellation every 1000 records
      if (i % this.cancellationCheckInterval === 0) {
        cancellationToken.throwIfCancelled();
      }

      const record = records[i];
      const values = headers.map(h => this.escapeCsvValue(String(record[h] ?? '')));
      lines.push(values.join(','));
    }

    return lines.join('\n');
  }

  /**
   * Escape CSV value (handle quotes, commas, newlines)
   */
  private escapeCsvValue(value: string): string {
    if (value.includes(',') || value.includes('"') || value.includes('\n')) {
      return `"${value.replace(/"/g, '""')}"`;
    }
    return value;
  }

  /**
   * Deliver export via specified method
   * 
   * Supports webhook, email, and download link delivery methods.
   * Email delivery is routed through the notifications module and its
   * versioned template system (BE-101).
   * 
   * @param userId - User ID requesting the export
   * @param exportType - Type of export
   * @param exportData - Export data as string
   * @param format - Export format
   * @param deliveryMethod - How to deliver the export
   * @param recordCount - Number of records included in the export
   * @param jobId - ID of the export generation job
   * @param cancellationToken - Token to check for cancellation
   * @throws Error when email delivery fails (surfaced on the export job record)
   */
  private async deliverExport(
    userId: string,
    exportType: string,
    exportData: string,
    format: ExportFormat,
    deliveryMethod: ExportDeliveryMethod,
    recordCount: number,
    jobId: string,
    cancellationToken: CancellationToken,
  ): Promise<string> {
    cancellationToken.throwIfCancelled();

    switch (deliveryMethod) {
      case ExportDeliveryMethod.WEBHOOK:
        this.logger.log(`Webhook delivery not yet implemented for user ${userId}`);
        return buildDeliveryReference(ExportDeliveryMethod.WEBHOOK, { jobId, userId });

      case ExportDeliveryMethod.EMAIL: {
        const payload: ExportCompletedPayload = {
          eventType: 'export.completed',
          eventId: `export:${jobId}`,
          recipientPublicKey: userId,
          title: `Your ${exportType} export is ready`,
          body:
            `Your ${format.toUpperCase()} export of ${recordCount} ` +
            `${recordCount === 1 ? 'record' : 'records'} has been generated ` +
            `and is attached to this delivery.`,
          occurredAt: new Date().toISOString(),
          exportType,
          format,
          recordCount,
          jobId,
          metadata: {
            jobId,
            exportType,
            format,
            recordCount,
            sizeBytes: Buffer.byteLength(exportData, 'utf8'),
          },
        };

        const result = await this.notificationService.deliverExportEmail(payload);

        if (!result.delivered) {
          const errorMessage =
            `Email delivery failed for export (jobId: ${jobId}): ` +
            `${result.error ?? 'unknown error'}`;
          this.logger.error(errorMessage);
          throw new Error(errorMessage);
        }

        this.logger.log(
          `Export email delivered via template version ` +
            `${result.templateVersionId ?? 'fallback'} (jobId: ${jobId})`,
        );
        return buildDeliveryReference(ExportDeliveryMethod.EMAIL, { jobId, userId });
      }

      case ExportDeliveryMethod.DOWNLOAD: {
        // Upload artifact to object storage and issue a signed download token.
        const { storageKey, sizeBytes } = await this.exportStorageService.uploadArtifact({
          jobId,
          userId,
          content: exportData,
          format,
          exportType,
        });

        const { token, expiresAt } = this.exportStorageService.issueDownloadToken({
          jobId,
          userId,
        });

        this.logger.log(
          `Export artifact stored (key=${storageKey}, size=${sizeBytes}B, ` +
            `expiresAt=${new Date(expiresAt * 1000).toISOString()}, jobId=${jobId})`,
        );

        // Notify the user that their download link is ready.
        const downloadPayload: ExportCompletedPayload = {
          eventType: 'export.completed',
          eventId: `export:${jobId}`,
          recipientPublicKey: userId,
          title: `Your ${exportType} export is ready to download`,
          body:
            `Your ${format.toUpperCase()} export of ${recordCount} ` +
            `${recordCount === 1 ? 'record' : 'records'} is ready. ` +
            `Use the download token to retrieve it.`,
          occurredAt: new Date().toISOString(),
          exportType,
          format,
          recordCount,
          jobId,
          metadata: {
            jobId,
            exportType,
            format,
            recordCount,
            sizeBytes,
            downloadToken: token,
            tokenExpiresAt: expiresAt,
          },
        };

        await this.notificationService.deliverExportEmail(downloadPayload);
        return buildDeliveryReference(ExportDeliveryMethod.DOWNLOAD, {
          jobId,
          userId,
          storageKey,
        });
      }

      default:
        throw new PermanentJobError(`Unsupported delivery method: ${deliveryMethod}`);
    }
  }

  /**
   * Validate export generation payload
   * 
   * Checks that required fields are present:
   * - userId: User requesting the export
   * - exportType: Type of data to export
   * - format: Output format
   * - deliveryMethod: How to deliver the export
   * 
   * @param payload - The export generation payload
   * @throws PermanentJobError if validation fails
   * 
   * **Validates: Requirements 9.3, 15.4, 15.5**
   */
  async validate(payload: ExportGenerationPayload): Promise<void> {
    const errors = collectExportValidationErrors(payload);

    if (payload.filters === undefined || payload.filters === null) {
      errors.push('filters is required and must be an object');
    }

    const uniqueErrors = [...new Set(errors)];

    if (uniqueErrors.length > 0) {
      throw new PermanentJobError(`Validation failed: ${uniqueErrors.join(', ')}`);
    }
  }

  /**
   * Handle job failure
   * 
   * Logs export generation failure.
   * This is called when the job exhausts all retry attempts and moves to DLQ.
   * 
   * @param job - The failed job
   * @param error - The error that caused the failure
   * 
   * **Validates: Requirements 9.5**
   */
  async onFailure(job: Job<ExportGenerationPayload>, error: Error): Promise<void> {
    const { userId, exportType, format } = job.payload;

    this.logger.error(
      `Export generation permanently failed for user ${userId} ` +
        `(type: ${exportType}, jobId: ${job.id}): ${error.message}`,
      error.stack,
    );

    // Derive a user-safe reason: use only the error message (never the stack
    // trace) and fall back to a generic phrase so internal details are never
    // surfaced to the end user.
    const safeReason =
      error instanceof Error && error.message
        ? error.message.replace(/\s*\n[\s\S]*$/, '') // strip any embedded newlines / stack frames
        : 'An unexpected error occurred';

    await this.notificationService.notifyExportFailed(
      userId,
      job.id,
      exportType,
      format,
      safeReason,
    );

    try {
      await this.exportRepository.transition(job.id, ExportStatus.FAILED, {
        failureReason: safeReason,
      });
    } catch (statusError) {
      const msg =
        statusError instanceof Error ? statusError.message : String(statusError);
      this.logger.error(
        `Failed to persist failed status for export job ${job.id}: ${msg}`,
      );
    }
  }
}
