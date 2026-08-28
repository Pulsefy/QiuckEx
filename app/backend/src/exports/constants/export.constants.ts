import {
  ExportDeliveryMethod,
  ExportFormat,
  ExportStatus,
  ExportType,
} from '../enums/export.enums';

export const EXPORT_JOBS_TABLE = 'export_jobs';

export const EXPORT_TYPE_VALUES = Object.values(ExportType);

export const EXPORT_FORMAT_VALUES = Object.values(ExportFormat);

export const EXPORT_DELIVERY_METHOD_VALUES = Object.values(
  ExportDeliveryMethod,
);

export const EXPORT_ENQUEUED_MESSAGE = 'Export job enqueued successfully';

export const EXPORT_ERROR_CODES = {
  JOB_NOT_FOUND: 'EXPORT_JOB_NOT_FOUND',
  INVALID_TRANSITION: 'EXPORT_INVALID_TRANSITION',
} as const;

export const EXPORT_STATUS_TRANSITIONS: Record<ExportStatus, ExportStatus[]> = {
  [ExportStatus.QUEUED]: [ExportStatus.RUNNING, ExportStatus.FAILED],
  [ExportStatus.RUNNING]: [ExportStatus.COMPLETED, ExportStatus.FAILED],
  [ExportStatus.COMPLETED]: [],
  [ExportStatus.FAILED]: [],
};

export const DELIVERY_REFERENCE_PREFIX = {
  [ExportDeliveryMethod.EMAIL]: 'email',
  [ExportDeliveryMethod.WEBHOOK]: 'webhook',
  [ExportDeliveryMethod.DOWNLOAD]: 'download',
} as const;
