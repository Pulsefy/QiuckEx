import {
  EXPORT_DELIVERY_METHOD_VALUES,
  EXPORT_FORMAT_VALUES,
  EXPORT_TYPE_VALUES,
} from '../constants/export.constants';
import {
  ExportDeliveryMethod,
  ExportFormat,
  ExportType,
} from '../enums/export.enums';

export interface ExportRequestInput {
  userId?: unknown;
  exportType?: unknown;
  format?: unknown;
  deliveryMethod?: unknown;
  filters?: unknown;
}

export function isPlainObject(
  value: unknown,
): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function isExportType(value: unknown): value is ExportType {
  return (
    typeof value === 'string' &&
    (EXPORT_TYPE_VALUES as string[]).includes(value)
  );
}

export function isExportFormat(value: unknown): value is ExportFormat {
  return (
    typeof value === 'string' &&
    (EXPORT_FORMAT_VALUES as string[]).includes(value)
  );
}

export function isExportDeliveryMethod(
  value: unknown,
): value is ExportDeliveryMethod {
  return (
    typeof value === 'string' &&
    (EXPORT_DELIVERY_METHOD_VALUES as string[]).includes(value)
  );
}

export function collectExportValidationErrors(
  input: ExportRequestInput,
): string[] {
  const errors: string[] = [];

  if (!input.userId || typeof input.userId !== 'string' || !input.userId.trim()) {
    errors.push('userId is required and must be a non-empty string');
  }

  if (!isExportType(input.exportType)) {
    errors.push(
      `exportType is required and must be one of: ${EXPORT_TYPE_VALUES.join(', ')}`,
    );
  }

  if (!isExportFormat(input.format)) {
    errors.push(
      `format is required and must be one of: ${EXPORT_FORMAT_VALUES.join(', ')}`,
    );
  }

  if (!isExportDeliveryMethod(input.deliveryMethod)) {
    errors.push(
      `deliveryMethod is required and must be one of: ${EXPORT_DELIVERY_METHOD_VALUES.join(', ')}`,
    );
  }

  if (
    input.filters !== undefined &&
    input.filters !== null &&
    !isPlainObject(input.filters)
  ) {
    errors.push('filters must be a plain object');
  }

  return errors;
}

export function normalizeExportFilters(
  filters: unknown,
): Record<string, unknown> {
  if (filters === undefined || filters === null) {
    return {};
  }

  if (!isPlainObject(filters)) {
    return {};
  }

  return filters;
}
