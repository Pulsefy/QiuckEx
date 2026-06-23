export type RateLimitGroup =
  | "public"
  | "public_abuse"
  | "authenticated"
  | "webhooks";
export type RateLimitWindow = "burst" | "sustained";
export type RateLimitKeyType = "user_id" | "api_key" | "ip";

export const RATE_LIMIT_GROUP_METADATA_KEY = "rate_limit_group";
export const THROTTLER_BURST_NAME = "burst";
export const THROTTLER_SUSTAINED_NAME = "sustained";

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

export function isTestnetEnvironment(
  env: Record<string, string | undefined> = process.env,
): boolean {
  const network = (
    env["STELLAR_NETWORK"] ??
    env["NETWORK"] ??
    "testnet"
  ).toLowerCase();

  return network === "testnet";
}

/**
 * Public endpoints that fan out to Horizon/RPC and are common abuse targets
 * during contributor testing and public demos.
 */
export function isAbuseSensitiveRoute(path: string): boolean {
  const normalized = path.toLowerCase();

  return (
    normalized.includes("/stellar/quote") ||
    (normalized.includes("/links") && normalized.endsWith("/metadata")) ||
    (normalized.includes("/links") && normalized.endsWith("/scan"))
  );
}

function resolvePublicAbuseDefaults(
  env: Record<string, string | undefined> = process.env,
): GroupConfig {
  const testnet = isTestnetEnvironment(env);

  return {
    burst: {
      limit: Number(
        env["RATE_LIMIT_PUBLIC_ABUSE_BURST_LIMIT"] ?? (testnet ? 5 : 8),
      ),
      ttlMs: Number(
        env["RATE_LIMIT_PUBLIC_ABUSE_BURST_TTL_MS"] ?? 10_000,
      ),
    },
    sustained: {
      limit: Number(
        env["RATE_LIMIT_PUBLIC_ABUSE_SUSTAINED_LIMIT"] ?? (testnet ? 15 : 30),
      ),
      ttlMs: Number(
        env["RATE_LIMIT_PUBLIC_ABUSE_SUSTAINED_TTL_MS"] ?? 60_000,
      ),
    },
  };
}

export function buildRateLimitConfig(
  env: Record<string, string | undefined> = process.env,
): RateLimitConfig {
  return {
    groups: {
      public: {
        burst: {
          limit: Number(env["RATE_LIMIT_PUBLIC_BURST_LIMIT"] ?? 10),
          ttlMs: Number(env["RATE_LIMIT_PUBLIC_BURST_TTL_MS"] ?? 10_000),
        },
        sustained: {
          limit: Number(env["RATE_LIMIT_PUBLIC_SUSTAINED_LIMIT"] ?? 20),
          ttlMs: Number(
            env["RATE_LIMIT_PUBLIC_SUSTAINED_TTL_MS"] ?? 60_000,
          ),
        },
      },
      public_abuse: resolvePublicAbuseDefaults(env),
      authenticated: {
        burst: {
          limit: Number(
            env["RATE_LIMIT_AUTHENTICATED_BURST_LIMIT"] ?? 40,
          ),
          ttlMs: Number(
            env["RATE_LIMIT_AUTHENTICATED_BURST_TTL_MS"] ?? 10_000,
          ),
        },
        sustained: {
          limit: Number(
            env["RATE_LIMIT_AUTHENTICATED_SUSTAINED_LIMIT"] ?? 120,
          ),
          ttlMs: Number(
            env["RATE_LIMIT_AUTHENTICATED_SUSTAINED_TTL_MS"] ?? 60_000,
          ),
        },
      },
      webhooks: {
        burst: {
          limit: Number(env["RATE_LIMIT_WEBHOOKS_BURST_LIMIT"] ?? 20),
          ttlMs: Number(
            env["RATE_LIMIT_WEBHOOKS_BURST_TTL_MS"] ?? 10_000,
          ),
        },
        sustained: {
          limit: Number(
            env["RATE_LIMIT_WEBHOOKS_SUSTAINED_LIMIT"] ?? 60,
          ),
          ttlMs: Number(
            env["RATE_LIMIT_WEBHOOKS_SUSTAINED_TTL_MS"] ?? 60_000,
          ),
        },
      },
    },
    keyOrder: parseKeyOrder(env["RATE_LIMIT_KEY_ORDER"]),
  };
}

export const throttlerConfig: RateLimitConfig = buildRateLimitConfig();

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
