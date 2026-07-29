import { BadRequestException, GoneException, NotFoundException } from "@nestjs/common";
import { QuoteService } from "./quote.service";
import type { PathPreviewRow } from "./path-preview.service";

const MOCK_PATH: PathPreviewRow = {
  sourceAmount: "100.0000000",
  sourceAsset: "XLM",
  destinationAmount: "10.0000000",
  destinationAsset: "USDC:GA5Z…KZVN",
  hopCount: 0,
  pathHops: [],
  rateDescription: "0.100000 (dest/source in smallest units)",
};

interface TestQuoteService {
  pathPreview: { previewPaths: jest.Mock };
  getCacheKey(dto: unknown): string;
  cache: Map<string, { fetchedAt: number }>;
  store: Map<string, { fetchedAt: number; expiresAt: Date }>;
}

function makeService(paths: PathPreviewRow[] = [MOCK_PATH]) {
  const mockPreview = {
    previewPaths: jest.fn().mockResolvedValue({ paths, horizonUrl: "https://horizon-testnet.stellar.org" }),
  };
  return new QuoteService(mockPreview as never);
}

const BASE_DTO = {
  destinationAmount: "10.5",
  destinationAsset: { code: "USDC", issuer: "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN" },
  sourceAssets: [{ code: "XLM" }],
};

describe("QuoteService", () => {
  describe("createQuote", () => {
    it("returns a quote with id, expiry, slippage-adjusted source amount, and fee breakdown", async () => {
      const svc = makeService();
      const result = await svc.createQuote(BASE_DTO);

      expect(result.quoteId).toMatch(/^qx_[a-f0-9]{24}$/);
      expect(new Date(result.expiresAt).getTime()).toBeGreaterThan(Date.now());
      expect(result.maxSlippageBps).toBe(50);
      expect(result.paths[0].sourceAmountWithSlippage).toBe("100.5000000"); // 0.5% of 100
      expect(result.paths[0].feeBreakdown).toEqual({
        networkFee: "0.0000100",
        platformFee: "0.1000000",
        totalFee: "0.1000000",
      });
    });

    it("uses custom slippage and TTL", async () => {
      const svc = makeService();
      const result = await svc.createQuote({ ...BASE_DTO, maxSlippageBps: 100, ttlSeconds: 60 });

      expect(result.maxSlippageBps).toBe(100);
      const ttlMs = new Date(result.expiresAt).getTime() - Date.now();
      expect(ttlMs).toBeGreaterThan(55_000);
      expect(ttlMs).toBeLessThanOrEqual(60_000);
    });

    it("throws NO_PATH_FOUND when Horizon returns no paths", async () => {
      const svc = makeService([]);
      await expect(svc.createQuote(BASE_DTO)).rejects.toThrow(BadRequestException);
      await expect(svc.createQuote(BASE_DTO)).rejects.toMatchObject({
        response: { code: "NO_PATH_FOUND" },
      });
    });

    it("includes preflight stub when requested", async () => {
      const svc = makeService();
      const result = await svc.createQuote({ ...BASE_DTO, preflight: true });
      expect(result.preflight).toEqual({ feasible: true });
    });
  });

  describe("getQuote", () => {
    it("returns a stored quote by id", async () => {
      const svc = makeService();
      const created = await svc.createQuote(BASE_DTO);
      const fetched = svc.getQuote(created.quoteId);
      expect(fetched.quoteId).toBe(created.quoteId);
    });

    it("throws QUOTE_NOT_FOUND for unknown id", () => {
      const svc = makeService();
      expect(() => svc.getQuote("qx_unknown")).toThrow(NotFoundException);
    });

    it("throws QUOTE_EXPIRED for an expired quote", async () => {
      const svc = makeService();
      const created = await svc.createQuote({ ...BASE_DTO, ttlSeconds: 5 });

      // Manually expire by manipulating the store
      const testSvc = svc as unknown as TestQuoteService;
      testSvc.store.get(created.quoteId)!.expiresAt = new Date(Date.now() - 1000);

      expect(() => svc.getQuote(created.quoteId)).toThrow(GoneException);
    });
  });

  describe("caching and revalidation", () => {
    it("caches the path preview results on first request (cache miss)", async () => {
      const svc = makeService();
      const testSvc = svc as unknown as TestQuoteService;
      const previewSpy = jest.spyOn(testSvc.pathPreview, "previewPaths");

      const res1 = await svc.createQuote(BASE_DTO);
      expect(res1.cacheSource).toBe("miss");
      expect(res1.age).toBe(0);
      expect(previewSpy).toHaveBeenCalledTimes(1);

      // Second request with same parameters should hit cache
      const res2 = await svc.createQuote(BASE_DTO);
      expect(res2.cacheSource).toBe("hit");
      expect(res2.age).toBe(0);
      expect(previewSpy).toHaveBeenCalledTimes(1); // Still 1 call!

      // Unique quote ID for both
      expect(res1.quoteId).not.toBe(res2.quoteId);
      // Both exist in store
      expect(svc.getQuote(res1.quoteId).quoteId).toBe(res1.quoteId);
      expect(svc.getQuote(res2.quoteId).quoteId).toBe(res2.quoteId);
    });

    it("bypasses cache and updates it when revalidate is true", async () => {
      const svc = makeService();
      const testSvc = svc as unknown as TestQuoteService;
      const previewSpy = jest.spyOn(testSvc.pathPreview, "previewPaths");

      const res1 = await svc.createQuote(BASE_DTO);
      expect(res1.cacheSource).toBe("miss");
      expect(previewSpy).toHaveBeenCalledTimes(1);

      // Revalidate: true
      const res2 = await svc.createQuote({ ...BASE_DTO, revalidate: true });
      expect(res2.cacheSource).toBe("miss");
      expect(previewSpy).toHaveBeenCalledTimes(2);

      // Next request without revalidate should be a hit (from the updated cache entry)
      const res3 = await svc.createQuote(BASE_DTO);
      expect(res3.cacheSource).toBe("hit");
      expect(previewSpy).toHaveBeenCalledTimes(2);
    });

    it("expires cache after CACHE_TTL_MS has elapsed", async () => {
      const svc = makeService();
      const testSvc = svc as unknown as TestQuoteService;
      const previewSpy = jest.spyOn(testSvc.pathPreview, "previewPaths");

      const res1 = await svc.createQuote(BASE_DTO);
      expect(res1.cacheSource).toBe("miss");
      expect(previewSpy).toHaveBeenCalledTimes(1);

      // Manually manipulate cache entry timestamp to be 11 seconds in past (CACHE_TTL_MS is 10s)
      const key = testSvc.getCacheKey(BASE_DTO);
      testSvc.cache.get(key)!.fetchedAt = Date.now() - 11_000;

      const res2 = await svc.createQuote(BASE_DTO);
      expect(res2.cacheSource).toBe("miss");
      expect(previewSpy).toHaveBeenCalledTimes(2);
    });

    it("tracks quote age dynamically over time on retrieval", async () => {
      const svc = makeService();
      const res = await svc.createQuote(BASE_DTO);
      expect(res.age).toBe(0);

      // Manually manipulate the fetchedAt in store to simulate passage of 5 seconds
      const testSvc = svc as unknown as TestQuoteService;
      const entry = testSvc.store.get(res.quoteId);
      entry!.fetchedAt = Date.now() - 5000;

      const fetched = svc.getQuote(res.quoteId);
      expect(fetched.age).toBe(5);
    });

    it("uses different cache entries for different slippage settings", async () => {
      const svc = makeService();
      const testSvc = svc as unknown as TestQuoteService;
      const previewSpy = jest.spyOn(testSvc.pathPreview, "previewPaths");

      const res1 = await svc.createQuote({ ...BASE_DTO, maxSlippageBps: 50 });
      expect(res1.cacheSource).toBe("miss");
      expect(previewSpy).toHaveBeenCalledTimes(1);

      const res2 = await svc.createQuote({ ...BASE_DTO, maxSlippageBps: 100 });
      expect(res2.cacheSource).toBe("miss");
      expect(previewSpy).toHaveBeenCalledTimes(2);
    });
  });
});
