import {
  ExportDeliveryMethod,
  ExportFormat,
  ExportStatus,
  ExportType,
} from '../enums/export.enums';
import { EXPORT_ERROR_CODES } from '../constants/export.constants';

export interface ExportRecord {
  id: string;
  jobId: string;
  userId: string;
  exportType: ExportType;
  format: ExportFormat;
  deliveryMethod: ExportDeliveryMethod;
  filters: Record<string, unknown>;
  status: ExportStatus;
  deliveryReference: string | null;
  failureReason: string | null;
  queuedAt: Date;
  startedAt: Date | null;
  completedAt: Date | null;
  failedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface CreateExportRecordInput {
  jobId: string;
  userId: string;
  exportType: ExportType;
  format: ExportFormat;
  deliveryMethod: ExportDeliveryMethod;
  filters: Record<string, unknown>;
}

export interface ExportStatusView {
  jobId: string;
  status: ExportStatus;
  exportType: ExportType;
  format: ExportFormat;
  deliveryMethod: ExportDeliveryMethod;
  queuedAt: string;
  startedAt: string | null;
  completedAt: string | null;
  failedAt: string | null;
  deliveryReference?: string;
  failureReason?: string;
}

export interface EnqueueExportResult {
  jobId: string;
  status: ExportStatus;
  message: string;
}

export interface ExportJobRow {
  id: string;
  job_id: string;
  user_id: string;
  export_type: string;
  format: string;
  delivery_method: string;
  filters: Record<string, unknown>;
  status: string;
  delivery_reference: string | null;
  failure_reason: string | null;
  queued_at: string;
  started_at: string | null;
  completed_at: string | null;
  failed_at: string | null;
  created_at: string;
  updated_at: string;
}

export class ExportRecordNotFoundError extends Error {
  readonly code = EXPORT_ERROR_CODES.JOB_NOT_FOUND;

  constructor(jobId: string) {
    super(`Export job not found: ${jobId}`);
    this.name = 'ExportRecordNotFoundError';
  }
}

export class ExportInvalidTransitionError extends Error {
  readonly code = EXPORT_ERROR_CODES.INVALID_TRANSITION;

  constructor(from: ExportStatus, to: ExportStatus) {
    super(`Cannot transition export from '${from}' to '${to}'`);
    this.name = 'ExportInvalidTransitionError';
  }
}
