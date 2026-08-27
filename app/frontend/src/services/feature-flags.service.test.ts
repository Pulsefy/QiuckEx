import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  FEATURE_FLAGS_SESSION_STORAGE_KEY,
} from '@/config/feature-flags.config';
import { fetchFeatureFlags } from './feature-flags.service';

describe('fetchFeatureFlags', () => {
  const originalFetch = global.fetch;
  const originalWindow = global.window;

  beforeEach(() => {
    vi.stubEnv('NEXT_PUBLIC_QUICKEX_API_URL', 'http://localhost:mock');
    global.fetch = vi.fn();
    Object.defineProperty(global, 'window', {
      configurable: true,
      value: {
        sessionStorage: {
          getItem: vi.fn(),
          setItem: vi.fn(),
        },
      },
    });
  });

  afterEach(() => {
    global.fetch = originalFetch;
    Object.defineProperty(global, 'window', {
      configurable: true,
      value: originalWindow,
    });
    vi.unstubAllEnvs();
  });

  it('maps an enabled snapshot and disables unsafe rollout states', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        flags: [
          { key: 'bulk_invoicing_v2', enabled: true, killSwitch: false, rolloutPercentage: 100 },
          { key: 'partial_rollout', enabled: true, killSwitch: false, rolloutPercentage: 50 },
          { key: 'killed_flag', enabled: true, killSwitch: true, rolloutPercentage: 100 },
        ],
      }),
    });

    await expect(fetchFeatureFlags()).resolves.toEqual({
      bulk_invoicing_v2: true,
      partial_rollout: false,
      killed_flag: false,
    });
    expect(global.fetch).toHaveBeenCalledWith(
      'http://localhost:mock/feature-flags/snapshot',
      expect.objectContaining({ cache: 'no-store' }),
    );
  });

  it('returns safe defaults when the snapshot fails', async () => {
    global.fetch = vi.fn().mockRejectedValue(new Error('offline'));
    const consoleSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

    await expect(fetchFeatureFlags()).resolves.toEqual({ bulk_invoicing_v2: false });

    expect(consoleSpy).toHaveBeenCalledWith(
      'Failed to load feature flags. Using safe defaults.',
      expect.any(Error),
    );
    consoleSpy.mockRestore();
  });

  it('uses the session cache unless explicitly refreshed', async () => {
    const getItem = window.sessionStorage.getItem as ReturnType<typeof vi.fn>;
    getItem.mockReturnValue(JSON.stringify({ bulk_invoicing_v2: true }));

    await expect(fetchFeatureFlags()).resolves.toEqual({ bulk_invoicing_v2: true });
    expect(global.fetch).not.toHaveBeenCalled();

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ flags: [] }),
    });
    await expect(fetchFeatureFlags(true)).resolves.toEqual({ bulk_invoicing_v2: false });
    expect(window.sessionStorage.setItem).toHaveBeenCalledWith(
      FEATURE_FLAGS_SESSION_STORAGE_KEY,
      JSON.stringify({ bulk_invoicing_v2: false }),
    );
  });
});