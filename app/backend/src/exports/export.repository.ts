import { Injectable, Logger } from '@nestjs/common';
import { SupabaseService } from '../supabase/supabase.service';
import { EXPORT_JOBS_TABLE } from './constants/export.constants';
import { ExportStatus } from './enums/export.enums';
import {
  ExportInvalidTransitionError,
  ExportRecordNotFoundError,
  type CreateExportRecordInput,
  type ExportJobRow,
  type ExportRecord,
} from './types/export.types';
import { canTransition } from './utils/export-status.util';
import { mapRowToExportRecord } from './utils/export-record.mapper';

export interface ExportTransitionExtras {
  deliveryReference?: string;
  failureReason?: string;
}

@Injectable()
export class ExportRepository {
  private readonly logger = new Logger(ExportRepository.name);

  constructor(private readonly supabase: SupabaseService) {}

  private get client() {
    return this.supabase.getClient();
  }

  async create(input: CreateExportRecordInput): Promise<ExportRecord> {
    const now = new Date().toISOString();
    const { data, error } = await this.client
      .from(EXPORT_JOBS_TABLE)
      .insert({
        job_id: input.jobId,
        user_id: input.userId,
        export_type: input.exportType,
        format: input.format,
        delivery_method: input.deliveryMethod,
        filters: input.filters,
        status: ExportStatus.QUEUED,
        queued_at: now,
      })
      .select()
      .single();

    if (error || !data) {
      const message = error?.message ?? 'unknown error';
      this.logger.error(`Failed to create export record: ${message}`);
      throw new Error(`Failed to persist export record: ${message}`);
    }

    return mapRowToExportRecord(data as ExportJobRow);
  }

  async findByJobId(jobId: string): Promise<ExportRecord | null> {
    const { data, error } = await this.client
      .from(EXPORT_JOBS_TABLE)
      .select('*')
      .eq('job_id', jobId)
      .maybeSingle();

    if (error) {
      this.logger.error(
        `Failed to look up export record for job ${jobId}: ${error.message}`,
      );
      throw new Error(`Failed to look up export record: ${error.message}`);
    }

    if (!data) {
      return null;
    }

    return mapRowToExportRecord(data as ExportJobRow);
  }

  async transition(
    jobId: string,
    status: ExportStatus,
    extras: ExportTransitionExtras = {},
  ): Promise<ExportRecord> {
    const current = await this.findByJobId(jobId);

    if (!current) {
      throw new ExportRecordNotFoundError(jobId);
    }

    if (!canTransition(current.status, status)) {
      throw new ExportInvalidTransitionError(current.status, status);
    }

    if (current.status === status) {
      return current;
    }

    const now = new Date();
    const updateData: Record<string, unknown> = {
      status,
      updated_at: now.toISOString(),
    };

    if (status === ExportStatus.RUNNING) {
      updateData.started_at = now.toISOString();
    }

    if (status === ExportStatus.COMPLETED) {
      updateData.completed_at = now.toISOString();
      updateData.delivery_reference = extras.deliveryReference ?? null;
    }

    if (status === ExportStatus.FAILED) {
      updateData.failed_at = now.toISOString();
      updateData.failure_reason = extras.failureReason ?? null;
    }

    const { data, error } = await this.client
      .from(EXPORT_JOBS_TABLE)
      .update(updateData)
      .eq('job_id', jobId)
      .select()
      .single();

    if (error || !data) {
      const message = error?.message ?? 'unknown error';
      this.logger.error(
        `Failed to transition export ${jobId} to ${status}: ${message}`,
      );
      throw new Error(`Failed to update export status: ${message}`);
    }

    return mapRowToExportRecord(data as ExportJobRow);
  }
}
