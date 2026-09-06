import {
  ExportDeliveryMethod,
  ExportFormat,
  ExportStatus,
  ExportType,
} from '../enums/export.enums';
import type { ExportJobRow, ExportRecord } from '../types/export.types';

export function mapRowToExportRecord(row: ExportJobRow): ExportRecord {
  return {
    id: row.id,
    jobId: row.job_id,
    userId: row.user_id,
    exportType: row.export_type as ExportType,
    format: row.format as ExportFormat,
    deliveryMethod: row.delivery_method as ExportDeliveryMethod,
    filters: row.filters ?? {},
    status: row.status as ExportStatus,
    deliveryReference: row.delivery_reference,
    failureReason: row.failure_reason,
    queuedAt: new Date(row.queued_at),
    startedAt: row.started_at ? new Date(row.started_at) : null,
    completedAt: row.completed_at ? new Date(row.completed_at) : null,
    failedAt: row.failed_at ? new Date(row.failed_at) : null,
    createdAt: new Date(row.created_at),
    updatedAt: new Date(row.updated_at),
  };
}
