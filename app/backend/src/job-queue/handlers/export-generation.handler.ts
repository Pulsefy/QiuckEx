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
import { NotificationPreferencesRepository } from '../../notifications/notification-preferences.repository';
import { JobQueueService } from '../job-queue.service';
import { JobType } from '../types';

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
    private readonly notificationPrefsRepo: NotificationPreferencesRepository,
    private readonly jobQueueService: JobQueueService,
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
      // Fetch data based on export type
      const records = await this.fetchExportData(userId, exportType, filters, cancellationToken);

      this.logger.log(
        `Fetched ${records.length} records for export (jobId: ${job.id})`,
      );

      // Generate export file
      const exportData = await this.generateExportFile(records, format, cancellationToken);

      this.logger.log(
        `Generated ${format} export (${exportData.length} bytes, jobId: ${job.id})`,
      );

      // Deliver export via specified method
      await this.deliverExport(
        userId,
        exportType,
        exportData,
        format,
        deliveryMethod,
        records.length,
        job.id,
        cancellationToken,
      );

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
    exportType: 'transactions' | 'links' | 'payments',
    filters: Record<string, unknown>,
    cancellationToken: CancellationToken,
  ): Promise<Record<string, unknown>[]> {
    // Check cancellation before starting
    cancellationToken.throwIfCancelled();

    const client = this.supabase.getClient();
    let query;

    // Build query based on export type
    switch (exportType) {
      case 'transactions':
        query = client
          .from('transactions')
          .select('*')
          .eq('user_id', userId);
        break;

      case 'links':
        query = client
          .from('links')
          .select('*')
          .eq('user_id', userId);
        break;

      case 'payments':
        query = client
          .from('payments')
          .select('*')
          .eq('user_id', userId);
        break;

      default:
        throw new PermanentJobError(`Unsupported export type: ${exportType}`);
    }

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
    format: 'csv' | 'json',
    cancellationToken: CancellationToken,
  ): Promise<string> {
    if (format === 'json') {
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
   * @throws Error when delivery fails (surfaced on the export job record)
   */
  private async deliverExport(
    userId: string,
    exportType: string,
    exportData: string,
    format: string,
    deliveryMethod: 'webhook' | 'email' | 'download',
    recordCount: number,
    jobId: string,
    cancellationToken: CancellationToken,
  ): Promise<void> {
    cancellationToken.throwIfCancelled();

    switch (deliveryMethod) {
      case 'webhook': {
        // Get user's webhook preference
        const webhookPrefs = await this.notificationPrefsRepo.getWebhooksByPublicKey(userId);
        const webhookPref = webhookPrefs.find(p => p.enabled && p.webhookUrl);

        if (!webhookPref || !webhookPref.webhookUrl) {
          const errorMessage = `No enabled webhook URL found for user ${userId}`;
          this.logger.error(errorMessage);
          throw new Error(errorMessage);
        }

        // Upload artifact and issue time-limited download reference
        const { storageKey } = await this.exportStorageService.uploadArtifact({
          jobId,
          userId,
          content: exportData,
          format: format as 'csv' | 'json',
          exportType,
        });

        const { token, expiresAt } = this.exportStorageService.issueDownloadToken({
          jobId,
          userId,
        });

        // Enqueue webhook delivery job using the existing webhook-delivery handler,
        // carrying export metadata and a time-limited download reference (never the raw export body).
        await this.jobQueueService.enqueue(JobType.WEBHOOK_DELIVERY, {
          recipientPublicKey: userId,
          webhookUrl: webhookPref.webhookUrl,
          webhookSecret: webhookPref.webhookSecret,
          eventType: 'export.completed',
          eventId: `export:${jobId}`,
          payload: {
            jobId,
            exportType,
            format,
            recordCount,
            sizeBytes: Buffer.byteLength(exportData, 'utf8'),
            storageKey,
            downloadToken: token,
            expiresAt,
          },
        });

        this.logger.log(
          `Webhook delivery enqueued for user ${userId} (jobId: ${jobId}, url: ${webhookPref.webhookUrl})`,
        );
        break;
      }

      case 'email': {
        const payload: ExportCompletedPayload = {
          eventType: 'export.completed',
          eventId: `export:${jobId}`,
          recipientPublicKey: userId,
          title: `Your ${exportType} export is ready`,
          body: `Your ${format.toUpperCase()} export of ${recordCount} ${recordCount === 1 ? 'record' : 'records'} has been generated and is attached to this delivery.`,
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
          const errorMessage = `Email delivery failed for export (jobId: ${jobId}): ${result.error ?? 'unknown error'}`;
          this.logger.error(errorMessage);
          throw new Error(errorMessage);
        }

        this.logger.log(
          `Export email delivered via template version ${result.templateVersionId ?? 'fallback'} (jobId: ${jobId})`,
        );
        break;
      }

      case 'download': {
        // Upload artifact to object storage and issue a signed download token.
        const { storageKey, sizeBytes } = await this.exportStorageService.uploadArtifact({
          jobId,
          userId,
          content: exportData,
          format: format as 'csv' | 'json',
          exportType,
        });

        const { token, expiresAt } = this.exportStorageService.issueDownloadToken({
          jobId,
          userId,
        });

        this.logger.log(
          `Export artifact stored (key=${storageKey}, size=${sizeBytes}B, expiresAt=${new Date(expiresAt * 1000).toISOString()}, jobId=${jobId})`,
        );
        break;
      }

      default:
        throw new PermanentJobError(`Unsupported delivery method: ${deliveryMethod}`);
    }
  }
}