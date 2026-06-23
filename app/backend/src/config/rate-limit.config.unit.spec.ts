import {
  buildRateLimitConfig,
  isAbuseSensitiveRoute,
  isTestnetEnvironment,
} from "./rate-limit.config";

describe("rate-limit.config", () => {
  describe("isTestnetEnvironment", () => {
    it("returns true when STELLAR_NETWORK is testnet", () => {
      expect(
        isTestnetEnvironment({ STELLAR_NETWORK: "testnet", NETWORK: "mainnet" }),
      ).toBe(true);
    });

    it("returns false when network is mainnet", () => {
      expect(
        isTestnetEnvironment({ STELLAR_NETWORK: "mainnet", NETWORK: "mainnet" }),
      ).toBe(false);
    });
  });

  describe("isAbuseSensitiveRoute", () => {
    it("matches quote, metadata, and scan routes", () => {
      expect(isAbuseSensitiveRoute("/stellar/quote")).toBe(true);
      expect(isAbuseSensitiveRoute("/stellar/quote/abc-123")).toBe(true);
      expect(isAbuseSensitiveRoute("/links/metadata")).toBe(true);
      expect(isAbuseSensitiveRoute("/links/scan")).toBe(true);
    });

    it("does not match unrelated routes", () => {
      expect(isAbuseSensitiveRoute("/health")).toBe(false);
      expect(isAbuseSensitiveRoute("/stellar/verified-assets")).toBe(false);
    });
  });

  describe("buildRateLimitConfig", () => {
    it("applies tighter public_abuse defaults on testnet", () => {
      const config = buildRateLimitConfig({ STELLAR_NETWORK: "testnet" });

      expect(config.groups.public_abuse.burst.limit).toBe(5);
      expect(config.groups.public_abuse.sustained.limit).toBe(15);
    });

    it("relaxes public_abuse defaults on mainnet", () => {
      const config = buildRateLimitConfig({ STELLAR_NETWORK: "mainnet" });

      expect(config.groups.public_abuse.burst.limit).toBe(8);
      expect(config.groups.public_abuse.sustained.limit).toBe(30);
    });

    it("honors explicit public_abuse overrides", () => {
      const config = buildRateLimitConfig({
        STELLAR_NETWORK: "testnet",
        RATE_LIMIT_PUBLIC_ABUSE_BURST_LIMIT: "12",
        RATE_LIMIT_PUBLIC_ABUSE_SUSTAINED_LIMIT: "40",
      });

      expect(config.groups.public_abuse.burst.limit).toBe(12);
      expect(config.groups.public_abuse.sustained.limit).toBe(40);
    });
  });
});
