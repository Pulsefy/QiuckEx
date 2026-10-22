export type RateLimitGroup = "public" | "authenticated" | "webhooks";
export type RateLimitTier = "public-read" | "search" | "mutation" | "export";
export type RateLimitWindow = "burst" | "sustained";
export type RateLimitKeyType = "user_id" | "api_key" | "ip";

export const RATE_LIMIT_GROUP_METADATA_KEY = "rate_limit_group";
export const RATE_LIMIT_TIER_METADATA_KEY = "rate_limit_tier";
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

type TierConfig = {
  burst: GroupWindowConfig;
  sustained: GroupWindowConfig;
};

export type RateLimitConfig = {
  groups: Record<RateLimitGroup, GroupConfig>;
  tiers: Record<RateLimitTier, TierConfig>;
  keyOrder: RateLimitKeyType[];
  allowlist: {
    cidrs: string[];
    apiKeys: string[];
    userIds: string[];
  };
  /**
   * Number of trusted reverse-proxy hops to skip when deriving the
   * client IP from X-Forwarded-For. 0 means X-Forwarded-For is never trusted
   * and the real socket address is always used.
   */
  trustedProxyHops: number;
  /**
   * Explicit allowlist of proxy IPs/CIDRs. When non-empty, a request is
   * only considered to have come from a trusted proxy if the immediate socket
   * peer matches one of these entries.
   */
  trustedProxies: string[];
};

const DEFAULT_KEY_ORDER: RateLimitKeyType[] = ["api_key", "user_id", "ip"];

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

function parseTrustedProxyHops(raw?: string): number {
  if (!raw) return 0;
  const parsed = Number.parseInt(raw.trim(), 10);
  if (!Number.isFinite(parsed) || parsed < 0) return 0;
  return parsed;
}

// Testnet-specific defaults
const isTestnet = process.env["NETWORK"] === "testnet";
const TESTNET_PUBLIC_BURST_LIMIT = 20;
const TESTNET_PUBLIC_SUSTAINED_LIMIT = 60;
const TESTNET_AUTH_BURST_LIMIT = 80;
const TESTNET_AUTH_SUSTAINED_LIMIT = 240;

const TESTNET_TIER_PUBLIC_READ_BURST_LIMIT = 40;
const TESTNET_TIER_PUBLIC_READ_SUSTAINED_LIMIT = 120;
const TESTNET_TIER_SEARCH_BURST_LIMIT = 20;
const TESTNET_TIER_SEARCH_SUSTAINED_LIMIT = 60;
const TESTNET_TIER_MUTATION_BURST_LIMIT = 30;
const TESTNET_TIER_MUTATION_SUSTAINED_LIMIT = 90;
const TESTNET_TIER_EXPORT_BURST_LIMIT = 5;
const TESTNET_TIER_EXPORT_SUSTAINED_LIMIT = 15;

export const throttlerConfig: RateLimitConfig = {
  groups: {
    public: {
      burst: {
        limit: Number(process.env["RATE_LIMIT_PUBLIC_BURST_LIMIT"] ?? (isTestnet ? TESTNET_PUBLIC_BURST_LIMIT : 10)),
        ttlMs: Number(process.env["RATE_LIMIT_PUBLIC_BURST_TTL_MS"] ?? 10_000),
      },
      sustained: {
        limit: Number(process.env["RATE_LIMIT_PUBLIC_SUSTAINED_LIMIT"] ?? (isTestnet ? TESTNET_PUBLIC_SUSTAINED_LIMIT : 20)),
        ttlMs: Number(
          process.env["RATE_LIMIT_PUBLIC_SUSTAINED_TTL_MS"] ?? 60_000,
        ),
      },
    },
    authenticated: {
      burst: {
        limit: Number(
          process.env["RATE_LIMIT_AUTHENTICATED_BURST_LIMIT"] ?? (isTestnet ? TESTNET_AUTH_BURST_LIMIT : 40),
        ),
        ttlMs: Number(
          process.env["RATE_LIMIT_AUTHENTICATED_BURST_TTL_MS"] ?? 10_000,
        ),
      },
      sustained: {
        limit: Number(
          process.env["RATE_LIMIT_AUTHENTICATED_SUSTAINED_LIMIT"] ?? (isTestnet ? TESTNET_AUTH_SUSTAINED_LIMIT : 120),
        ),
        ttlMs: Number(
          process.env["RATE_LIMIT_AUTHENTICATED_SUSTAINED_TTL_MS"] ?? 60_000,
        ),
      },
    },
    webhooks: {
      burst: {
        limit: Number(process.env["RATE_LIMIT_WEBHOOKS_BURST_LIMIT"] ?? 20),
        ttlMs: Number(
          process.env["RATE_LIMIT_WEBHOOKS_BURST_TTL_MS"] ?? 10_000,
        ),
      },
      sustained: {
        limit: Number(process.env["RATE_LIMIT_WEBHOOKS_SUSTAINED_LIMIT"] ?? 60),
        ttlMs: Number(
          process.env["RATE_LIMIT_WEBHOOKS_SUSTAINED_TTL_MS"] ?? 60_000,
        ),
      },
    },
  },
  tiers: {
    "public-read": {
      burst: {
        limit: Number(process.env["RATE_LIMIT_TIER_PUBLIC_READ_BURST_LIMIT"] ?? (isTestnet ? TESTNET_TIER_PUBLIC_READ_BURST_LIMIT : 20)),
        ttlMs: Number(process.env["RATE_LIMIT_TIER_PUBLIC_READ_BURST_TTL_MS"] ?? 10_000),
      },
      sustained: {
        limit: Number(process.env["RATE_LIMIT_TIER_PUBLIC_READ_SUSTAINED_LIMIT"] ?? (isTestnet ? TESTNET_TIER_PUBLIC_READ_SUSTAINED_LIMIT : 60)),
        ttlMs: Number(process.env["RATE_LIMIT_TIER_PUBLIC_READ_SUSTAINED_TTL_MS"] ?? 60_000),
      },
    },
    search: {
      burst: {
        limit: Number(process.env["RATE_LIMIT_TIER_SEARCH_BURST_LIMIT"] ?? (isTestnet ? TESTNET_TIER_SEARCH_BURST_LIMIT : 10)),
        ttlMs: Number(process.env["RATE_LIMIT_TIER_SEARCH_BURST_TTL_MS"] ?? 10_000),
      },
      sustained: {
        limit: Number(process.env["RATE_LIMIT_TIER_SEARCH_SUSTAINED_LIMIT"] ?? (isTestnet ? TESTNET_TIER_SEARCH_SUSTAINED_LIMIT : 30)),
        ttlMs: Number(process.env["RATE_LIMIT_TIER_SEARCH_SUSTAINED_TTL_MS"] ?? 60_000),
      },
    },
    mutation: {
      burst: {
        limit: Number(process.env["RATE_LIMIT_TIER_MUTATION_BURST_LIMIT"] ?? (isTestnet ? TESTNET_TIER_MUTATION_BURST_LIMIT : 15)),
        ttlMs: Number(process.env["RATE_LIMIT_TIER_MUTATION_BURST_TTL_MS"] ?? 10_000),
      },
      sustained: {
        limit: Number(process.env["RATE_LIMIT_TIER_MUTATION_SUSTAINED_LIMIT"] ?? (isTestnet ? TESTNET_TIER_MUTATION_SUSTAINED_LIMIT : 45)),
        ttlMs: Number(process.env["RATE_LIMIT_TIER_MUTATION_SUSTAINED_TTL_MS"] ?? 60_000),
      },
    },
    export: {
      burst: {
        limit: Number(process.env["RATE_LIMIT_TIER_EXPORT_BURST_LIMIT"] ?? (isTestnet ? TESTNET_TIER_EXPORT_BURST_LIMIT : 3)),
        ttlMs: Number(process.env["RATE_LIMIT_TIER_EXPORT_BURST_TTL_MS"] ?? 10_000),
      },
      sustained: {
        limit: Number(process.env["RATE_LIMIT_TIER_EXPORT_SUSTAINED_LIMIT"] ?? (isTestnet ? TESTNET_TIER_EXPORT_SUSTAINED_LIMIT : 10)),
        ttlMs: Number(process.env["RATE_LIMIT_TIER_EXPORT_SUSTAINED_TTL_MS"] ?? 60_000),
      },
    },
  },
  keyOrder: parseKeyOrder(process.env["RATE_LIMIT_KEY_ORDER"]),
  allowlist: {
    cidrs: parseAllowlist<string>(process.env["RATE_LIMIT_ALLOWLIST_CIDRS"]),
    apiKeys: parseAllowlist<string>(process.env["RATE_LIMIT_ALLOWLIST_API_KEYS"]),
    userIds: parseAllowlist<string>(process.env["RATE_LIMIT_ALLOWLIST_USER_IDS"]),
  },
  trustedProxyHops: parseTrustedProxyHops(process.env["RATE_LIMIT_TRUSTED_PROXY_HOPS"]),
  trustedProxies: parseAllowlist<string>(process.env["RATE_LIMIT_TRUSTED_PROXIES"]),
};

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
