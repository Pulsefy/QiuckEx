import { BranchPreviewEnvironment } from './branch-preview.model';
import { PreviewExpiryThresholds } from './branch-preview-expiry.config';

export type PreviewAutoExpiryReason = 'ttl_expired' | 'inactivity' | 'max_age';

export interface PreviewExpiryEvaluation {
  shouldExpire: boolean;
  reason?: PreviewAutoExpiryReason;
}

function effectiveLastActivity(preview: BranchPreviewEnvironment): Date {
  return preview.lastActivityAt ?? preview.updatedAt;
}

/**
 * Determines whether an active preview should be auto-expired.
 * Shared and explicitly exempt environments are never expired by the worker.
 */
export function evaluatePreviewAutoExpiry(
  preview: BranchPreviewEnvironment,
  thresholds: PreviewExpiryThresholds,
  now: Date,
): PreviewExpiryEvaluation {
  if (!preview.isActive) {
    return { shouldExpire: false };
  }

  if (preview.expiryExempt || preview.isShared) {
    return { shouldExpire: false };
  }

  const nowMs = now.getTime();

  if (preview.expiresAt && nowMs >= preview.expiresAt.getTime()) {
    return { shouldExpire: true, reason: 'ttl_expired' };
  }

  const inactiveForMs = nowMs - effectiveLastActivity(preview).getTime();
  if (inactiveForMs >= thresholds.inactivityMs) {
    return { shouldExpire: true, reason: 'inactivity' };
  }

  const ageMs = nowMs - preview.createdAt.getTime();
  if (ageMs >= thresholds.maxAgeMs) {
    return { shouldExpire: true, reason: 'max_age' };
  }

  return { shouldExpire: false };
}
