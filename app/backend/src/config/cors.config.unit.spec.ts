import { buildCorsOptions } from "./cors.config";
import { CorsOptions } from "@nestjs/common/interfaces/external/cors-options.interface";

type OriginCallback = (err: Error | null, allow?: boolean) => void;
type OriginFn = (origin: string | undefined, cb: OriginCallback) => void;

function resolveOrigin(
  options: CorsOptions,
  origin: string | undefined,
): Promise<boolean> {
  return new Promise((resolve, reject) => {
    (options.origin as OriginFn)(origin, (err, allowed) => {
      if (err) reject(err);
      else resolve(!!allowed);
    });
  });
}

describe("buildCorsOptions", () => {
  describe("non-production", () => {
    it("returns origin: true in development", () => {
      const opts = buildCorsOptions({ nodeEnv: "development", allowedOrigins: [] });
      expect(opts.origin).toBe(true);
    });

    it("returns origin: true in test", () => {
      const opts = buildCorsOptions({ nodeEnv: "test", allowedOrigins: [] });
      expect(opts.origin).toBe(true);
    });
  });

  describe("production — static origins", () => {
    const opts = buildCorsOptions({
      nodeEnv: "production",
      allowedOrigins: ["https://quickex.to", "https://app.quickex.to"],
    });

    it("allows a listed origin", async () => {
      await expect(resolveOrigin(opts, "https://quickex.to")).resolves.toBe(true);
    });

    it("allows a second listed origin", async () => {
      await expect(resolveOrigin(opts, "https://app.quickex.to")).resolves.toBe(true);
    });

    it("blocks an unlisted origin", async () => {
      await expect(resolveOrigin(opts, "https://evil.com")).rejects.toThrow(
        "Origin not allowed",
      );
    });

    it("allows requests with no origin (server-to-server)", async () => {
      await expect(resolveOrigin(opts, undefined)).resolves.toBe(true);
    });
  });

  describe("production — Vercel preview URLs", () => {
    const opts = buildCorsOptions({
      nodeEnv: "production",
      allowedOrigins: ["https://quickex.to"],
      vercelProject: "quickex-frontend",
    });

    it("allows a valid Vercel preview URL", async () => {
      await expect(
        resolveOrigin(opts, "https://quickex-frontend-abc123-team.vercel.app"),
      ).resolves.toBe(true);
    });

    it("blocks a preview URL for a different project", async () => {
      await expect(
        resolveOrigin(opts, "https://other-project-abc123-team.vercel.app"),
      ).rejects.toThrow("Origin not allowed");
    });

    it("blocks a URL that tries to spoof the project name", async () => {
      await expect(
        resolveOrigin(opts, "https://evil-quickex-frontend-abc.vercel.app"),
      ).rejects.toThrow("Origin not allowed");
    });

    it("still allows the static production origin", async () => {
      await expect(resolveOrigin(opts, "https://quickex.to")).resolves.toBe(true);
    });
  });

  describe("production — no wildcard", () => {
    it("does not set origin to true or '*' in production", () => {
      const opts = buildCorsOptions({
        nodeEnv: "production",
        allowedOrigins: ["https://quickex.to"],
      });
      expect(opts.origin).not.toBe(true);
      expect(opts.origin).not.toBe("*");
    });
  });

  describe("credentials and headers", () => {
    it("sets credentials: true in production", () => {
      const opts = buildCorsOptions({ nodeEnv: "production", allowedOrigins: [] });
      expect(opts.credentials).toBe(true);
    });

    it("includes Authorization in allowedHeaders", () => {
      const opts = buildCorsOptions({ nodeEnv: "production", allowedOrigins: [] });
      expect(opts.allowedHeaders).toContain("Authorization");
    });

    it("includes X-API-Key in allowedHeaders", () => {
      const opts = buildCorsOptions({ nodeEnv: "production", allowedOrigins: [] });
      expect(opts.allowedHeaders).toContain("X-API-Key");
    });
  });
});
