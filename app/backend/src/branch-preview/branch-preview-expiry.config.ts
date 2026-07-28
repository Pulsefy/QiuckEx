const DAY_MS = 24 * 60 * 60 * 1000;

/** Default inactivity window before a contributor preview is considered stale. */
export const DEFAULT_PREVIEW_INACTIVITY_THRESHOLD_MS = 3 * DAY_MS;

/** Default maximum lifetime for ephemeral contributor previews. */
export const DEFAULT_PREVIEW_MAX_AGE_MS = 14 * DAY_MS;

export interface PreviewExpiryThresholds {
  inactivityMs: number;
  maxAgeMs: number;
}

export function resolvePreviewExpiryThresholds(
  env: NodeJS.ProcessEnv = process.env,
): PreviewExpiryThresholds {
  const inactivityRaw = env.PREVIEW_INACTIVITY_THRESHOLD_MS;
  const maxAgeRaw = env.PREVIEW_MAX_AGE_MS;

  const inactivityMs =
    inactivityRaw !== undefined && inactivityRaw !== ''
      ? Number(inactivityRaw)
      : DEFAULT_PREVIEW_INACTIVITY_THRESHOLD_MS;
  const maxAgeMs =
    maxAgeRaw !== undefined && maxAgeRaw !== ''
      ? Number(maxAgeRaw)
      : DEFAULT_PREVIEW_MAX_AGE_MS;

  if (!Number.isFinite(inactivityMs) || inactivityMs < 0) {
    throw new Error('PREVIEW_INACTIVITY_THRESHOLD_MS must be a non-negative number');
  }
  if (!Number.isFinite(maxAgeMs) || maxAgeMs < 0) {
    throw new Error('PREVIEW_MAX_AGE_MS must be a non-negative number');
  }

  return { inactivityMs, maxAgeMs };
}

export const PREVIEW_AUTO_EXPIRY_WORKER_ACTOR = 'system:preview-auto-expiry-worker';
export const BRANCH_PREVIEW_AUTO_EXPIRED_EVENT = 'branch.preview.auto_expired';
