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
    it("returns a quote with id, expiry, and slippage-adjusted source amount", async () => {
      const svc = makeService();
      const result = await svc.createQuote(BASE_DTO);

      expect(result.quoteId).toMatch(/^qx_[a-f0-9]{24}$/);
      expect(new Date(result.expiresAt).getTime()).toBeGreaterThan(Date.now());
      expect(result.maxSlippageBps).toBe(50);
      expect(result.paths[0].sourceAmountWithSlippage).toBe("100.5000000"); // 0.5% of 100
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
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const store: Map<string, { response: unknown; expiresAt: Date }> = (svc as any).store;
      store.get(created.quoteId)!.expiresAt = new Date(Date.now() - 1000);

      expect(() => svc.getQuote(created.quoteId)).toThrow(GoneException);
    });
  });
});
