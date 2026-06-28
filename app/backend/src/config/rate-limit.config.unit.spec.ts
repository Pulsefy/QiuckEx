import { parseRateLimitAllowlist } from "./rate-limit.config";

describe("parseRateLimitAllowlist", () => {
  it("returns empty lists when the env vars are unset", () => {
    const allowlist = parseRateLimitAllowlist({});

    expect(allowlist).toEqual({ ips: [], apiKeys: [] });
  });

  it("parses comma-separated IPs and API keys", () => {
    const allowlist = parseRateLimitAllowlist({
      RATE_LIMIT_ALLOWLIST_IPS: "203.0.113.7,198.51.100.4",
      RATE_LIMIT_ALLOWLIST_API_KEYS: "ci-token,contributor-token",
    });

    expect(allowlist.ips).toEqual(["203.0.113.7", "198.51.100.4"]);
    expect(allowlist.apiKeys).toEqual(["ci-token", "contributor-token"]);
  });

  it("trims whitespace and drops empty entries", () => {
    const allowlist = parseRateLimitAllowlist({
      RATE_LIMIT_ALLOWLIST_IPS: " 203.0.113.7 , , 198.51.100.4 ,",
      RATE_LIMIT_ALLOWLIST_API_KEYS: "  ci-token ,",
    });

    expect(allowlist.ips).toEqual(["203.0.113.7", "198.51.100.4"]);
    expect(allowlist.apiKeys).toEqual(["ci-token"]);
  });

  it("treats empty strings as no allowlist", () => {
    const allowlist = parseRateLimitAllowlist({
      RATE_LIMIT_ALLOWLIST_IPS: "",
      RATE_LIMIT_ALLOWLIST_API_KEYS: "",
    });

    expect(allowlist).toEqual({ ips: [], apiKeys: [] });
  });
});
