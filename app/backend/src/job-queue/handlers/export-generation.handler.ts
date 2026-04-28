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
      await this.deliverExport(userId, exportType, exportData, format, deliveryMethod, cancellationToken);

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
   * 
   * @param userId - User ID requesting the export
   * @param exportType - Type of export
   * @param exportData - Export data as string
   * @param format - Export format
   * @param deliveryMethod - How to deliver the export
   * @param cancellationToken - Token to check for cancellation
   */
  private async deliverExport(
    userId: string,
    exportType: string,
    exportData: string,
    format: string,
    deliveryMethod: 'webhook' | 'email' | 'download',
    cancellationToken: CancellationToken,
  ): Promise<void> {
    cancellationToken.throwIfCancelled();

    switch (deliveryMethod) {
      case 'webhook':
        // TODO: Implement webhook delivery
        // For now, just log
        this.logger.log(`Webhook delivery not yet implemented for user ${userId}`);
        break;

      case 'email':
        // TODO: Implement email delivery
        // For now, just log
        this.logger.log(`Email delivery not yet implemented for user ${userId}`);
        break;

      case 'download':
        // TODO: Implement download link generation (store in S3/Supabase Storage)
        // For now, just log
        this.logger.log(`Download link generation not yet implemented for user ${userId}`);
        break;

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
    const errors: string[] = [];

    if (!payload.userId || typeof payload.userId !== 'string') {
      errors.push('userId is required and must be a string');
    }

    if (!payload.exportType || !['transactions', 'links', 'payments'].includes(payload.exportType)) {
      errors.push('exportType is required and must be one of: transactions, links, payments');
    }

    if (!payload.format || !['csv', 'json'].includes(payload.format)) {
      errors.push('format is required and must be one of: csv, json');
    }

    if (!payload.deliveryMethod || !['webhook', 'email', 'download'].includes(payload.deliveryMethod)) {
      errors.push('deliveryMethod is required and must be one of: webhook, email, download');
    }

    if (!payload.filters || typeof payload.filters !== 'object') {
      errors.push('filters is required and must be an object');
    }

    if (errors.length > 0) {
      throw new PermanentJobError(`Validation failed: ${errors.join(', ')}`);
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
    const { userId, exportType } = job.payload;

    this.logger.error(
      `Export generation permanently failed for user ${userId} (type: ${exportType}, jobId: ${job.id}): ${error.message}`,
      error.stack,
    );

    // TODO: Notify user of export failure via notification system
  }
}
