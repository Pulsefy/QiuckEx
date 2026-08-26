/**
 * Client-safe flags returned by GET /feature-flags/snapshot.
 * Unknown flags are intentionally disabled so a missing rollout cannot expose a gated surface.
 */
export type FeatureFlagKey = 'bulk_invoicing_v2' | (string & {});

export type FeatureFlagValues = Record<string, boolean>;

export const DEFAULT_FEATURE_FLAGS: FeatureFlagValues = {
  bulk_invoicing_v2: false,
};

export const FEATURE_FLAGS_SESSION_STORAGE_KEY = 'quickex.feature-flags.v1';