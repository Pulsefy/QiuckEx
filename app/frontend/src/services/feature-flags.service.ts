import {
  DEFAULT_FEATURE_FLAGS,
  FEATURE_FLAGS_SESSION_STORAGE_KEY,
  FeatureFlagValues,
} from '@/config/feature-flags.config';
import { getQuickexApiBase } from '@/lib/api';

type FeatureFlagSnapshotEntry = {
  key: string;
  enabled: boolean;
  killSwitch: boolean;
  rolloutPercentage: number;
};

type FeatureFlagSnapshotResponse = {
  flags?: FeatureFlagSnapshotEntry[];
};

const normalizeFlags = (entries: FeatureFlagSnapshotEntry[]): FeatureFlagValues =>
  entries.reduce<FeatureFlagValues>((flags, entry) => {
    // Partial rollouts need user context, so the client stays disabled unless the
    // snapshot explicitly enables the flag for everyone.
    flags[entry.key] =
      entry.enabled && !entry.killSwitch && entry.rolloutPercentage >= 100;
    return flags;
  }, { ...DEFAULT_FEATURE_FLAGS });

const readSessionFlags = (): FeatureFlagValues | null => {
  if (typeof window === 'undefined') return null;

  try {
    const cached = window.sessionStorage.getItem(FEATURE_FLAGS_SESSION_STORAGE_KEY);
    if (!cached) return null;
    const parsed = JSON.parse(cached) as unknown;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
    return { ...DEFAULT_FEATURE_FLAGS, ...(parsed as FeatureFlagValues) };
  } catch {
    return null;
  }
};

const writeSessionFlags = (flags: FeatureFlagValues): void => {
  if (typeof window === 'undefined') return;

  try {
    window.sessionStorage.setItem(
      FEATURE_FLAGS_SESSION_STORAGE_KEY,
      JSON.stringify(flags),
    );
  } catch {
    // Storage can be unavailable in private browsing; the in-memory value still works.
  }
};

/** Loads a client-safe snapshot. Failure returns safe defaults and never blocks rendering. */
export const fetchFeatureFlags = async (
  forceRefresh = false,
): Promise<FeatureFlagValues> => {
  if (!forceRefresh) {
    const cached = readSessionFlags();
    if (cached) return cached;
  }

  try {
    const response = await fetch(`${getQuickexApiBase()}/feature-flags/snapshot`, {
      headers: { Accept: 'application/json' },
      cache: 'no-store',
    });
    if (!response.ok) throw new Error(`Feature flag fetch failed (${response.status})`);

    const payload = (await response.json()) as FeatureFlagSnapshotResponse;
    const flags = normalizeFlags(payload.flags ?? []);
    writeSessionFlags(flags);
    return flags;
  } catch (error) {
    console.warn('Failed to load feature flags. Using safe defaults.', error);
    return { ...DEFAULT_FEATURE_FLAGS };
  }
};