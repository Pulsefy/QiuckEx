import { ExecutionContext } from "@nestjs/common";
import { Test, TestingModule } from "@nestjs/testing";
import {
  ThrottlerException,
  ThrottlerGuard,
  ThrottlerModule,
  ThrottlerRequest,
} from "@nestjs/throttler";
import { CustomThrottlerGuard } from "./custom-throttler.guard";
import {
  RATE_LIMIT_GROUP_METADATA_KEY,
  THROTTLER_BURST_NAME,
  THROTTLER_SUSTAINED_NAME,
  throttlerConfig,
} from "../../config/rate-limit.config";
import { MetricsService } from "../../metrics/metrics.service";

type ReqShape = {
  headers?: Record<string, string>;
  user?: { id?: string };
  ip?: string;
  baseUrl?: string;
  route?: { path?: string };
  path?: string;
  originalUrl?: string;
  method?: string;
};

interface GuardSurface {
  handleRequest(requestProps: ThrottlerRequest): Promise<boolean>;
  getTracker(req: ReqShape): Promise<string>;
}

function buildContext(
  req: ReqShape,
  handler?: (...args: unknown[]) => unknown,
  classRef?: object,
): ExecutionContext {
  const response = {
    setHeader: jest.fn(),
  };

  return {
    switchToHttp: () => ({
      getRequest: () => req,
      getResponse: () => response,
    }),
    getHandler: () => handler ?? (() => undefined),
    getClass: () => (classRef ?? class DummyController {}) as never,
  } as unknown as ExecutionContext;
}

function buildProps(
  context: ExecutionContext,
  throttlerName: string = THROTTLER_BURST_NAME,
): ThrottlerRequest {
  return {
    context,
    limit: 1,
    ttl: 1_000,
    throttler: { name: throttlerName, limit: 1, ttl: 1_000 },
    blockDuration: 0,
    generateKey: jest.fn(),
  } as unknown as ThrottlerRequest;
}

const throttlerProto = ThrottlerGuard.prototype as unknown as GuardSurface;

describe("CustomThrottlerGuard", () => {
  let guard: GuardSurface;
  let superHandleRequest: jest.SpyInstance;
  let metricsServiceRecordMock: jest.Mock;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      imports: [
        ThrottlerModule.forRoot([
          {
            name: THROTTLER_BURST_NAME,
            ttl: 10_000,
            limit: 10,
          },
          {
            name: THROTTLER_SUSTAINED_NAME,
            ttl: 60_000,
            limit: 20,
          },
        ]),
      ],
      providers: [
        CustomThrottlerGuard,
        {
          provide: MetricsService,
          useValue: {
            recordRateLimitedRequest: jest.fn(),
          },
        },
      ],
    }).compile();

    guard = module.get(CustomThrottlerGuard) as unknown as GuardSurface;
    metricsServiceRecordMock = module.get(MetricsService).recordRateLimitedRequest as jest.Mock;

    superHandleRequest = jest
      .spyOn(throttlerProto, "handleRequest")
      .mockResolvedValue(true);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it("uses public burst profile by default", async () => {
    const context = buildContext({
      ip: "127.0.0.1",
      baseUrl: "/links",
      route: { path: "/metadata" },
    });
    const props = buildProps(context, THROTTLER_BURST_NAME);

    await guard.handleRequest(props);

    expect(superHandleRequest).toHaveBeenCalledWith(
      expect.objectContaining({
        limit: throttlerConfig.groups.public.burst.limit,
        ttl: throttlerConfig.groups.public.burst.ttlMs,
      }),
    );
  });

  it("uses authenticated sustained profile when API key is present", async () => {
    const context = buildContext({
      headers: { "x-api-key": "trusted-client-key" },
      ip: "127.0.0.1",
      baseUrl: "/transactions",
      route: { path: "/" },
    });
    const props = buildProps(context, THROTTLER_SUSTAINED_NAME);

    await guard.handleRequest(props);

    expect(superHandleRequest).toHaveBeenCalledWith(
      expect.objectContaining({
        limit: throttlerConfig.groups.authenticated.sustained.limit,
        ttl: throttlerConfig.groups.authenticated.sustained.ttlMs,
      }),
    );
  });

  it("uses webhook profile when metadata tag is set", async () => {
    const handler = () => undefined;
    Reflect.defineMetadata(RATE_LIMIT_GROUP_METADATA_KEY, "webhooks", handler);

    const context = buildContext(
      { ip: "127.0.0.1", baseUrl: "/webhooks", route: { path: "/:publicKey" } },
      handler,
    );
    const props = buildProps(context, THROTTLER_BURST_NAME);

    await guard.handleRequest(props);

    expect(superHandleRequest).toHaveBeenCalledWith(
      expect.objectContaining({
        limit: throttlerConfig.groups.webhooks.burst.limit,
        ttl: throttlerConfig.groups.webhooks.burst.ttlMs,
      }),
    );
  });

  it("sets Retry-After header when throttled", async () => {
    const context = buildContext({
      ip: "127.0.0.1",
      baseUrl: "/links",
      route: { path: "/metadata" },
    });
    const props = buildProps(context, THROTTLER_BURST_NAME);

    superHandleRequest.mockRejectedValueOnce(new ThrottlerException());

    await expect(guard.handleRequest(props)).rejects.toBeInstanceOf(
      ThrottlerException,
    );

    const response = context.switchToHttp().getResponse() as {
      setHeader: jest.Mock;
    };

    expect(response.setHeader).toHaveBeenCalledWith(
      "Retry-After",
      Math.ceil(throttlerConfig.groups.public.burst.ttlMs / 1000).toString(),
    );
  });

  it("records rate limit metrics when throttled", async () => {
    const context = buildContext({
      ip: "127.0.0.1",
      baseUrl: "/links",
      route: { path: "/metadata" },
      method: "GET",
    });
    const props = buildProps(context, THROTTLER_BURST_NAME);

    superHandleRequest.mockRejectedValueOnce(new ThrottlerException());

    await expect(guard.handleRequest(props)).rejects.toBeInstanceOf(
      ThrottlerException,
    );

    expect(metricsServiceRecordMock).toHaveBeenCalledWith(
      "GET",
      "/metadata",
      "public",
      "ip",
    );
  });

  it("builds tracker from user id when available", async () => {
    const tracker = await guard.getTracker({
      user: { id: "user-42" },
      headers: { "x-api-key": "client-key" },
      ip: "10.0.0.7",
    });

    expect(tracker).toBe("user_id:user-42");
  });

  it("falls back to ip tracker when identity headers are absent", async () => {
    const tracker = await guard.getTracker({ ip: "10.0.0.9" });
    expect(tracker).toBe("ip:10.0.0.9");
  });
});
