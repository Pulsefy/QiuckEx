import { ExecutionContext, UnauthorizedException } from "@nestjs/common";
import * as bcrypt from "bcrypt";
import { ApiKeyGuard } from "./api-key.guard";
import { RATE_LIMITS } from "../../common/constants/rate-limit.constants";

jest.mock("bcrypt");

const mockBcryptCompare = bcrypt.compare as jest.MockedFunction<
  typeof bcrypt.compare
>;

/** Build a fake ExecutionContext and expose its underlying request object. */
function makeContext(headers: Record<string, string> = {}): {
  ctx: ExecutionContext;
  req: Record<string, unknown>;
} {
  const req: Record<string, unknown> = { headers };
  const ctx = {
    switchToHttp: () => ({ getRequest: () => req }),
  } as unknown as ExecutionContext;
  return { ctx, req };
}

describe("ApiKeyGuard", () => {
  let guard: ApiKeyGuard;
  const originalApiKeys = process.env.API_KEYS;

  beforeEach(() => {
    guard = new ApiKeyGuard();
    mockBcryptCompare.mockReset();
    process.env.API_KEYS = "";
  });

  afterAll(() => {
    process.env.API_KEYS = originalApiKeys;
  });

  // ---------------------------------------------------------------------------
  // Public access (no header)
  // ---------------------------------------------------------------------------
  describe("when no X-API-Key header is provided", () => {
    it("should return true and allow public access without touching bcrypt", async () => {
      const { ctx } = makeContext();

      const result = await guard.canActivate(ctx);

      expect(result).toBe(true);
      expect(mockBcryptCompare).not.toHaveBeenCalled();
    });

    it("should NOT annotate req.apiKey when no key is supplied", async () => {
      const { ctx, req } = makeContext();

      await guard.canActivate(ctx);

      expect(req["apiKey"]).toBeUndefined();
    });
  });

  // ---------------------------------------------------------------------------
  // Valid API key
  // ---------------------------------------------------------------------------
  describe("when a valid API key is provided", () => {
    it("should return true and annotate req.apiKey with the elevated rate limit", async () => {
      process.env.API_KEYS = "$2b$10$hashedvalue";
      mockBcryptCompare.mockResolvedValueOnce(true as never);

      const { ctx, req } = makeContext({ "x-api-key": "my-secret-key" });

      const result = await guard.canActivate(ctx);

      expect(result).toBe(true);
      expect(req["apiKey"]).toEqual({ rateLimit: RATE_LIMITS.API_KEY.limit });
    });

    it("should short-circuit after the first matching hash (not check the rest)", async () => {
      process.env.API_KEYS = "hash1,hash2,hash3";
      mockBcryptCompare
        .mockResolvedValueOnce(false as never) // hash1 misses
        .mockResolvedValueOnce(true as never); // hash2 hits – stop here

      const { ctx } = makeContext({ "x-api-key": "my-secret-key" });

      await guard.canActivate(ctx);

      expect(mockBcryptCompare).toHaveBeenCalledTimes(2);
    });
  });

  // ---------------------------------------------------------------------------
  // Invalid API key
  // ---------------------------------------------------------------------------
  describe("when an invalid API key is provided", () => {
    it("should throw UnauthorizedException when no hash matches", async () => {
      process.env.API_KEYS = "$2b$10$hashedvalue";
      mockBcryptCompare.mockResolvedValue(false as never);

      const { ctx } = makeContext({ "x-api-key": "wrong-key" });

      await expect(guard.canActivate(ctx)).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it("should include INVALID_API_KEY code in the exception response", async () => {
      process.env.API_KEYS = "$2b$10$hashedvalue";
      mockBcryptCompare.mockResolvedValue(false as never);

      const { ctx } = makeContext({ "x-api-key": "wrong-key" });

      await expect(guard.canActivate(ctx)).rejects.toMatchObject({
        response: { error: "INVALID_API_KEY" },
      });
    });

    it("should reject even when API_KEYS env is empty", async () => {
      process.env.API_KEYS = "";
      // bcrypt.compare is called zero times because there are no hashes to iterate
      const { ctx } = makeContext({ "x-api-key": "any-key" });

      await expect(guard.canActivate(ctx)).rejects.toThrow(
        UnauthorizedException,
      );
    });
  });
});
