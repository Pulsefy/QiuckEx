import { EXPORT_STATUS_TRANSITIONS } from '../constants/export.constants';
import { ExportStatus } from '../enums/export.enums';
import type { ExportRecord, ExportStatusView } from '../types/export.types';

export function canTransition(
  from: ExportStatus,
  to: ExportStatus,
): boolean {
  if (from === to) {
    return true;
  }

  return EXPORT_STATUS_TRANSITIONS[from].includes(to);
}

export function toIsoString(value: Date | null): string | null {
  return value ? value.toISOString() : null;
}

export function toExportStatusView(record: ExportRecord): ExportStatusView {
  const view: ExportStatusView = {
    jobId: record.jobId,
    status: record.status,
    exportType: record.exportType,
    format: record.format,
    deliveryMethod: record.deliveryMethod,
    queuedAt: record.queuedAt.toISOString(),
    startedAt: toIsoString(record.startedAt),
    completedAt: toIsoString(record.completedAt),
    failedAt: toIsoString(record.failedAt),
  };

  if (record.status === ExportStatus.COMPLETED && record.deliveryReference) {
    view.deliveryReference = record.deliveryReference;
  }

  if (record.status === ExportStatus.FAILED && record.failureReason) {
    view.failureReason = record.failureReason;
  }

  return view;
}
