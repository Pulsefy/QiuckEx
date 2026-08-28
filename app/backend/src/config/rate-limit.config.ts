import { Injectable } from "@nestjs/common";

import { AppConfigService } from "./app-config.service";

export type RateLimitGroup = "public" | "authenticated" | "webhooks";
export type RateLimitWindow = "burst" | "sustained";
export type RateLimitKeyType = "user_id" | "api_key" | "ip";

export type RateLimitProfileName =
  | "local"
  | "preview"
  | "staging"
  | "production"
  | "testnet";

export const RATE_LIMIT_GROUP_METADATA_KEY = "rate_limit_group";
export const THROTTLER_BURST_NAME = "burst";
export const THROTTLER_SUSTAINED_NAME = "sustained";

/**
 * A single rate-limit profile. Profiles ship with sensible defaults for a given
 * environment and can be overridden at runtime via environment variables
 * (see AppConfigService#rateLimitOverrides). `defaultLimit` is the baseline
 * sustained request limit per window for the `public` group; the per-group
 * limits are derived from it with fixed multipliers and can be overridden.
 */
export type RateLimitProfile = {
  defaultLimit: number;
  windowMs: number;
  apiKeyMultiplier: number;
};

/**
 * Profile defaults. These are pure constants — no `process.env` reads at
 * import time. Active profile and per-group overrides are resolved through
 * AppConfigService (see RateLimitConfigService) so config can change without
 * restarting the process in dev.
 */
export const RATE_LIMIT_PROFILES: Record<
  RateLimitProfileName,
  RateLimitProfile
> = {
  local: { defaultLimit: 20, windowMs: 60_000, apiKeyMultiplier: 6 },
  preview: { defaultLimit: 15, windowMs: 60_000, apiKeyMultiplier: 6 },
  staging: { defaultLimit: 10, windowMs: 60_000, apiKeyMultiplier: 6 },
  production: { defaultLimit: 10, windowMs: 60_000, apiKeyMultiplier: 4 },
  testnet: { defaultLimit: 20, windowMs: 60_000, apiKeyMultiplier: 6 },
};

type GroupWindowConfig = {
  limit: number;
  ttlMs: number;
};

type GroupConfig = {
  burst: GroupWindowConfig;
  sustained: GroupWindowConfig;
};

export type RateLimitConfig = {
  groups: Record<RateLimitGroup, GroupConfig>;
  keyOrder: RateLimitKeyType[];
  allowlist: {
    cidrs: string[];
    apiKeys: string[];
    userIds: string[];
  };
};

export type RateLimitOverrides = {
  public: Partial<{ burst: number; burstTtlMs: number; sustained: number; sustainedTtlMs: number }>;
  authenticated: Partial<{ burst: number; burstTtlMs: number; sustained: number; sustainedTtlMs: number }>;
  webhooks: Partial<{ burst: number; burstTtlMs: number; sustained: number; sustainedTtlMs: number }>;
  keyOrder: string;
  allowlistCidrs: string;
  allowlistApiKeys: string;
  allowlistUserIds: string;
};

const DEFAULT_KEY_ORDER: RateLimitKeyType[] = ["user_id", "api_key", "ip"];

function parseKeyOrder(raw?: string): RateLimitKeyType[] {
  if (!raw) return DEFAULT_KEY_ORDER;

  const tokens = raw
    .split(",")
    .map((t) => t.trim().toLowerCase())
    .filter(Boolean);

  const ordered = tokens.filter(
    (value): value is RateLimitKeyType =>
      value === "user_id" || value === "api_key" || value === "ip",
  );

  return ordered.length > 0 ? ordered : DEFAULT_KEY_ORDER;
}

function parseAllowlist<T>(raw?: string): T[] {
  if (!raw) return [];
  return raw.split(",").map((s) => s.trim()).filter(Boolean) as T[];
}

function numberOr(value: number | undefined, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value) && value > 0
    ? value
    : fallback;
}

/**
 * Static default configuration used by middleware that cannot participate in
 * Nest DI (e.g. decorators, guards instantiated outside the container). These
 * are pure constants and do not read `process.env` at import time — the live,
 * environment-driven configuration is provided by RateLimitConfigService.
 */
export const throttlerConfig: RateLimitConfig = (() => {
  const defaults = RATE_LIMIT_PROFILES.testnet;
  const burstTtlMs = Math.min(defaults.windowMs, 10_000);

  const publicSustained = defaults.defaultLimit;
  const publicBurst = Math.max(5, Math.round(publicSustained / 3));
  const authSustained = publicSustained * 4;
  const authBurst = Math.max(10, Math.round(authSustained / 3));
  const webhookSustained = Math.max(10, Math.round(publicSustained * 3));
  const webhookBurst = Math.max(10, Math.round(webhookSustained / 3));

  return {
    groups: {
      public: {
        burst: { limit: publicBurst, ttlMs: burstTtlMs },
        sustained: { limit: publicSustained, ttlMs: defaults.windowMs },
      },
      authenticated: {
        burst: { limit: authBurst, ttlMs: burstTtlMs },
        sustained: { limit: authSustained, ttlMs: defaults.windowMs },
      },
      webhooks: {
        burst: { limit: webhookBurst, ttlMs: burstTtlMs },
        sustained: { limit: webhookSustained, ttlMs: defaults.windowMs },
      },
    },
    keyOrder: DEFAULT_KEY_ORDER,
    allowlist: {
      cidrs: [],
      apiKeys: [],
      userIds: [],
    },
  };
})();

/**
 * Injectable, environment-driven rate-limit configuration.
 *
 * Resolves the active profile + per-group env overrides through AppConfigService
 * on every call so that changes take effect without restarting the process
 * (matters especially in dev / watch mode).
 */
@Injectable()
export class RateLimitConfigService {
  constructor(private readonly appConfig: AppConfigService) {}

  getProfileName(): RateLimitProfileName {
    return this.appConfig.rateLimitProfile;
  }

  getProfile(): RateLimitProfile {
    return RATE_LIMIT_PROFILES[this.getProfileName()];
  }

  getApiKeyMultiplier(): number {
    return this.getProfile().apiKeyMultiplier;
  }

  getGroupConfig(
    group: RateLimitGroup,
    window: RateLimitWindow,
  ): GroupWindowConfig {
    const overrides = this.appConfig.rateLimitOverrides;
    const groupOverrides = overrides[group];
    const windowMs = this.getProfile().windowMs;
    const burstTtlMs = Math.min(windowMs, 10_000);

    const defaults = this.deriveGroupBaselines();

    if (window === "burst") {
      return {
        limit: numberOr(groupOverrides.burst, defaults[group].burst.limit),
        ttlMs: numberOr(groupOverrides.burstTtlMs, defaults[group].burst.ttlMs),
      };
    }

    return {
      limit: numberOr(groupOverrides.sustained, defaults[group].sustained.limit),
      ttlMs: numberOr(
        groupOverrides.sustainedTtlMs,
        defaults[group].sustained.ttlMs,
      ),
    };
  }

  getFullConfig(): RateLimitConfig {
    const overrides = this.appConfig.rateLimitOverrides;

    return {
      groups: {
        public: {
          burst: this.getGroupConfig("public", "burst"),
          sustained: this.getGroupConfig("public", "sustained"),
        },
        authenticated: {
          burst: this.getGroupConfig("authenticated", "burst"),
          sustained: this.getGroupConfig("authenticated", "sustained"),
        },
        webhooks: {
          burst: this.getGroupConfig("webhooks", "burst"),
          sustained: this.getGroupConfig("webhooks", "sustained"),
        },
      },
      keyOrder: parseKeyOrder(overrides.keyOrder),
      allowlist: {
        cidrs: parseAllowlist<string>(overrides.allowlistCidrs),
        apiKeys: parseAllowlist<string>(overrides.allowlistApiKeys),
        userIds: parseAllowlist<string>(overrides.allowlistUserIds),
      },
    };
  }

  getThrottlerModuleProfiles(): Array<{
    name: string;
    ttl: number;
    limit: number;
  }> {
    return [
      {
        name: THROTTLER_BURST_NAME,
        ttl: this.getGroupConfig("public", "burst").ttlMs,
        limit: this.getGroupConfig("public", "burst").limit,
      },
      {
        name: THROTTLER_SUSTAINED_NAME,
        ttl: this.getGroupConfig("public", "sustained").ttlMs,
        limit: this.getGroupConfig("public", "sustained").limit,
      },
    ];
  }

  private deriveGroupBaselines(): Record<RateLimitGroup, GroupConfig> {
    const { defaultLimit, windowMs } = this.getProfile();
    const burstTtlMs = Math.min(windowMs, 10_000);

    const publicSustained = defaultLimit;
    const publicBurst = Math.max(5, Math.round(publicSustained / 3));
    const authSustained = publicSustained * 4;
    const authBurst = Math.max(10, Math.round(authSustained / 3));
    const webhookSustained = Math.max(10, Math.round(publicSustained * 3));
    const webhookBurst = Math.max(10, Math.round(webhookSustained / 3));

    return {
      public: {
        burst: { limit: publicBurst, ttlMs: burstTtlMs },
        sustained: { limit: publicSustained, ttlMs: windowMs },
      },
      authenticated: {
        burst: { limit: authBurst, ttlMs: burstTtlMs },
        sustained: { limit: authSustained, ttlMs: windowMs },
      },
      webhooks: {
        burst: { limit: webhookBurst, ttlMs: burstTtlMs },
        sustained: { limit: webhookSustained, ttlMs: windowMs },
      },
    };
  }
}

export const throttlerModuleProfiles = [
  {
    name: THROTTLER_BURST_NAME,
    ttl: throttlerConfig.groups.public.burst.ttlMs,
    limit: throttlerConfig.groups.public.burst.limit,
  },
  {
    name: THROTTLER_SUSTAINED_NAME,
    ttl: throttlerConfig.groups.public.sustained.ttlMs,
    limit: throttlerConfig.groups.public.sustained.limit,
  },
];
