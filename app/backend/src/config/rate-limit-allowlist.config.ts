/**
 * Rate-limit allowlist configuration.
 *
 * Trusted IPs and API keys listed here bypass throttling entirely.
 * This keeps CI pipelines and known contributor tooling friction-free
 * while still protecting public endpoints from abuse.
 *
 * Environment variables:
 *   RATE_LIMIT_ALLOWLIST_IPS  – comma-separated IPs (e.g. "127.0.0.1,::1")
 *   RATE_LIMIT_ALLOWLIST_KEYS – comma-separated plain-text API keys
 *   RATE_LIMIT_ALLOWLIST_ENABLED – "true" | "false" (default "true")
 */

export interface RateLimitAllowlistConfig {
  enabled: boolean;
  ips: Set<string>;
  apiKeys: Set<string>;
}

function parseList(raw?: string): Set<string> {
  if (!raw) return new Set();
  return new Set(
    raw
      .split(",")
      .map((v) => v.trim())
      .filter(Boolean),
  );
}

export function resolveAllowlistConfig(
  env: Record<string, string | undefined> = process.env,
): RateLimitAllowlistConfig {
  const enabled = (env["RATE_LIMIT_ALLOWLIST_ENABLED"] ?? "true").toLowerCase() !== "false";

  return {
    enabled,
    ips: parseList(env["RATE_LIMIT_ALLOWLIST_IPS"]),
    apiKeys: parseList(env["RATE_LIMIT_ALLOWLIST_KEYS"]),
  };
}

export const allowlistConfig = resolveAllowlistConfig();
