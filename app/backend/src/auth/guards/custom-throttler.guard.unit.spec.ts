import { ExecutionContext } from "@nestjs/common";
import { Test, TestingModule } from "@nestjs/testing";
import {
  ThrottlerGuard,
  ThrottlerModule,
  ThrottlerRequest,
} from "@nestjs/throttler";
import { CustomThrottlerGuard } from "./custom-throttler.guard";
import { RATE_LIMITS } from "../../common/constants/rate-limit.constants";

/**
 * Typed interface that surfaces the protected `handleRequest` method so we can
 * spy on and invoke it without resorting to `any`.
 */
interface ThrottlerGuardHandleRequest {
  handleRequest(requestProps: ThrottlerRequest): Promise<boolean>;
}

/** Build a fake ExecutionContext whose request optionally carries apiKey. */
function buildContext(apiKey?: { rateLimit: number }): ExecutionContext {
  const req: Record<string, unknown> = {};
  if (apiKey) req.apiKey = apiKey;
  return {
    switchToHttp: () => ({ getRequest: () => req }),
  } as unknown as ExecutionContext;
}

/** Minimal ThrottlerRequest fixture — only the fields our guard reads. */
function buildProps(
  context: ExecutionContext,
  limit = RATE_LIMITS.PUBLIC.limit,
): ThrottlerRequest {
  return {
    context,
    limit,
    ttl: 60_000,
    throttler: { name: "default", limit, ttl: 60_000 },
    blockDuration: 0,
    generateKey: jest.fn(),
  } as unknown as ThrottlerRequest;
}

/** Prototype cast — exposes protected handleRequest under a safe interface. */
const throttlerProto =
  ThrottlerGuard.prototype as unknown as ThrottlerGuardHandleRequest;

describe("CustomThrottlerGuard", () => {
  let guard: ThrottlerGuardHandleRequest;
  let superHandleRequest: jest.SpyInstance;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      imports: [
        ThrottlerModule.forRoot([
          { ttl: 60_000, limit: RATE_LIMITS.PUBLIC.limit },
        ]),
      ],
      providers: [CustomThrottlerGuard],
    }).compile();

    guard =
      module.get(CustomThrottlerGuard) as unknown as ThrottlerGuardHandleRequest;

    // Spy on the parent prototype via the typed interface — no `any` needed.
    superHandleRequest = jest
      .spyOn(throttlerProto, "handleRequest")
      .mockResolvedValue(true);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  // ---------------------------------------------------------------------------
  // Public traffic (no API key)
  // ---------------------------------------------------------------------------
  describe("without an API key on the request", () => {
    it("should forward the configured public limit to the parent guard", async () => {
      const context = buildContext();
      const props = buildProps(context, RATE_LIMITS.PUBLIC.limit);

      await guard.handleRequest(props);

      expect(superHandleRequest).toHaveBeenCalledWith(
        expect.objectContaining({ limit: RATE_LIMITS.PUBLIC.limit }),
      );
    });

    it("should allow the request through (200 scenario)", async () => {
      superHandleRequest.mockResolvedValue(true);
      const context = buildContext();
      const props = buildProps(context, RATE_LIMITS.PUBLIC.limit);

      const result = await guard.handleRequest(props);

      expect(result).toBe(true);
    });
  });

  // ---------------------------------------------------------------------------
  // Trusted API-key traffic
  // ---------------------------------------------------------------------------
  describe("with a valid API key on the request", () => {
    it("should substitute the elevated API-key limit", async () => {
      const context = buildContext({ rateLimit: RATE_LIMITS.API_KEY.limit });
      const props = buildProps(context, RATE_LIMITS.PUBLIC.limit);

      await guard.handleRequest(props);

      expect(superHandleRequest).toHaveBeenCalledWith(
        expect.objectContaining({ limit: RATE_LIMITS.API_KEY.limit }),
      );
    });

    it("should NOT use the public limit when an API key is present", async () => {
      const context = buildContext({ rateLimit: RATE_LIMITS.API_KEY.limit });
      const props = buildProps(context, RATE_LIMITS.PUBLIC.limit);

      await guard.handleRequest(props);

      const calledWith = superHandleRequest.mock.calls[0][0] as ThrottlerRequest;
      expect(calledWith.limit).not.toBe(RATE_LIMITS.PUBLIC.limit);
    });
  });

  // ---------------------------------------------------------------------------
  // Limit values are distinct
  // ---------------------------------------------------------------------------
  it("API_KEY limit should be higher than PUBLIC limit", () => {
    expect(RATE_LIMITS.API_KEY.limit).toBeGreaterThan(RATE_LIMITS.PUBLIC.limit);
  });
});
