import { BranchPreviewEnvironment } from './branch-preview.model';
import {
  DEFAULT_PREVIEW_INACTIVITY_THRESHOLD_MS,
  DEFAULT_PREVIEW_MAX_AGE_MS,
} from './branch-preview-expiry.config';
import { evaluatePreviewAutoExpiry } from './branch-preview-expiry.policy';

const thresholds = {
  inactivityMs: DEFAULT_PREVIEW_INACTIVITY_THRESHOLD_MS,
  maxAgeMs: DEFAULT_PREVIEW_MAX_AGE_MS,
};

function basePreview(overrides: Partial<BranchPreviewEnvironment> = {}): BranchPreviewEnvironment {
  const now = new Date('2026-07-24T12:00:00.000Z');
  return {
    id: 'preview-1',
    branchName: 'feat/test',
    apiUrl: 'https://api.example.com',
    frontendUrl: 'https://app.example.com',
    network: 'testnet',
    contractRegistryVersion: 'v1',
    isActive: true,
    isShared: false,
    expiryExempt: false,
    createdAt: new Date(now.getTime() - 60_000),
    updatedAt: now,
    lastActivityAt: now,
    ...overrides,
  };
}

describe('evaluatePreviewAutoExpiry', () => {
  const now = new Date('2026-07-24T12:00:00.000Z');

  it('does not expire shared environments even when stale', () => {
    const preview = basePreview({
      isShared: true,
      lastActivityAt: new Date(now.getTime() - thresholds.inactivityMs - 1),
    });
    expect(evaluatePreviewAutoExpiry(preview, thresholds, now).shouldExpire).toBe(false);
  });

  it('does not expire explicitly exempt environments', () => {
    const preview = basePreview({
      expiryExempt: true,
      createdAt: new Date(now.getTime() - thresholds.maxAgeMs - 1),
    });
    expect(evaluatePreviewAutoExpiry(preview, thresholds, now).shouldExpire).toBe(false);
  });

  it('expires at inactivity threshold boundary', () => {
    const preview = basePreview({
      lastActivityAt: new Date(now.getTime() - thresholds.inactivityMs),
    });
    const result = evaluatePreviewAutoExpiry(preview, thresholds, now);
    expect(result).toEqual({ shouldExpire: true, reason: 'inactivity' });
  });

  it('does not expire one millisecond before inactivity threshold', () => {
    const preview = basePreview({
      lastActivityAt: new Date(now.getTime() - thresholds.inactivityMs + 1),
    });
    expect(evaluatePreviewAutoExpiry(preview, thresholds, now).shouldExpire).toBe(false);
  });

  it('expires at max age threshold boundary', () => {
    const preview = basePreview({
      createdAt: new Date(now.getTime() - thresholds.maxAgeMs),
      lastActivityAt: now,
    });
    const result = evaluatePreviewAutoExpiry(preview, thresholds, now);
    expect(result).toEqual({ shouldExpire: true, reason: 'max_age' });
  });

  it('expires when expires_at is reached (ttl)', () => {
    const preview = basePreview({
      expiresAt: new Date(now.getTime() - 1),
      lastActivityAt: now,
    });
    const result = evaluatePreviewAutoExpiry(preview, thresholds, now);
    expect(result).toEqual({ shouldExpire: true, reason: 'ttl_expired' });
  });

  it('uses updatedAt when lastActivityAt is missing for inactivity', () => {
    const preview = basePreview({
      lastActivityAt: undefined,
      updatedAt: new Date(now.getTime() - thresholds.inactivityMs),
    });
    expect(evaluatePreviewAutoExpiry(preview, thresholds, now).reason).toBe('inactivity');
  });
});
