import { resolveAllowlistConfig } from "./rate-limit-allowlist.config";

describe("rate-limit-allowlist.config", () => {
  it("parses trusted IPs and API keys", () => {
    const config = resolveAllowlistConfig({
      RATE_LIMIT_ALLOWLIST_ENABLED: "true",
      RATE_LIMIT_ALLOWLIST_IPS: "127.0.0.1, ::1",
      RATE_LIMIT_ALLOWLIST_KEYS: "ci-key, contributor-key",
    });

    expect(config.enabled).toBe(true);
    expect(config.ips.has("127.0.0.1")).toBe(true);
    expect(config.ips.has("::1")).toBe(true);
    expect(config.apiKeys.has("ci-key")).toBe(true);
    expect(config.apiKeys.has("contributor-key")).toBe(true);
  });

  it("can disable the allowlist entirely", () => {
    const config = resolveAllowlistConfig({
      RATE_LIMIT_ALLOWLIST_ENABLED: "false",
      RATE_LIMIT_ALLOWLIST_IPS: "127.0.0.1",
      RATE_LIMIT_ALLOWLIST_KEYS: "ci-key",
    });

    expect(config.enabled).toBe(false);
  });
});
