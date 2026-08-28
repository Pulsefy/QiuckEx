import { DELIVERY_REFERENCE_PREFIX } from '../constants/export.constants';
import { ExportDeliveryMethod } from '../enums/export.enums';

export interface DeliveryReferenceInput {
  jobId: string;
  userId: string;
  storageKey?: string;
}

export function buildDeliveryReference(
  method: ExportDeliveryMethod,
  details: DeliveryReferenceInput,
): string {
  switch (method) {
    case ExportDeliveryMethod.DOWNLOAD:
      return (
        details.storageKey ??
        `${DELIVERY_REFERENCE_PREFIX.download}:${details.jobId}`
      );
    case ExportDeliveryMethod.EMAIL:
      return `${DELIVERY_REFERENCE_PREFIX.email}:export:${details.jobId}`;
    case ExportDeliveryMethod.WEBHOOK:
      return `${DELIVERY_REFERENCE_PREFIX.webhook}:${details.userId}`;
    default: {
      const exhaustive: never = method;
      return exhaustive;
    }
  }
}
