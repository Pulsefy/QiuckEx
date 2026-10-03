import { Test, TestingModule } from "@nestjs/testing";
import { ExecutionContext, ServiceUnavailableException } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { IndexerLagGuard } from "../indexer-lag.guard";
import { IndexerLagService } from "../indexer-lag.service";
import { AuditService } from "../../audit/audit.service";
import { MetricsService } from "../../metrics/metrics.service";
import { REQUIRE_INDEXER_LAG_CHECK_KEY } from "../requires-indexer-lag-check.decorator";

describe("IndexerLagGuard", () => {
  let guard: IndexerLagGuard;
  let reflector: Partial<Reflector>;
  let indexerLagService: Partial<IndexerLagService>;
  let auditService: Partial<AuditService>;
  let metricsService: Partial<MetricsService>;

  const mockExecutionContext = (requiresCheck: boolean) => {
    const req = {
      method: "GET",
      path: "/transactions",
      headers: { "x-user-id": "user-1" },
      route: { path: "/transactions" },
    };
    const res = {
      setHeader: jest.fn(),
    };
    return {
      getHandler: jest.fn(),
      getClass: jest.fn(),
      switchToHttp: () => ({
        getRequest: () => req,
        getResponse: () => res,
      }),
    } as unknown as ExecutionContext;
  };

  beforeEach(async () => {
    reflector = {
      getAllAndOverride: jest.fn(),
    };

    indexerLagService = {
      isBlocked: jest.fn(),
      getStatus: jest.fn().mockReturnValue({
        currentNetworkLedger: 150,
        lastIndexedLedger: 100,
        lagLedgers: 50,
        thresholdLedgers: 10,
        isLagging: true,
        isEnabled: true,
        isOverridden: false,
      }),
    };

    auditService = {
      log: jest.fn().mockResolvedValue(undefined),
    };

    metricsService = {
      recordIndexerLagGuardBlockedRequest: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        IndexerLagGuard,
        { provide: Reflector, useValue: reflector },
        { provide: IndexerLagService, useValue: indexerLagService },
        { provide: AuditService, useValue: auditService },
        { provide: MetricsService, useValue: metricsService },
      ],
    }).compile();

    guard = module.get<IndexerLagGuard>(IndexerLagGuard);
  });

  it("should allow request if route does not require indexer lag check", async () => {
    (reflector.getAllAndOverride as jest.fn).mockReturnValue(false);
    const ctx = mockExecutionContext(false);

    const result = await guard.canActivate(ctx);
    expect(result).toBe(true);
    expect(indexerLagService.isBlocked).not.toHaveBeenCalled();
  });

  it("should allow request if indexer is not blocked", async () => {
    (reflector.getAllAndOverride as jest.fn).mockReturnValue(true);
    (indexerLagService.isBlocked as jest.fn).mockReturnValue(false);
    const ctx = mockExecutionContext(true);

    const result = await guard.canActivate(ctx);
    expect(result).toBe(true);
  });

  it("should block request and throw ServiceUnavailableException with Retry-After when indexer is lagging", async () => {
    (reflector.getAllAndOverride as jest.fn).mockReturnValue(true);
    (indexerLagService.isBlocked as jest.fn).mockReturnValue(true);
    const ctx = mockExecutionContext(true);

    await expect(guard.canActivate(ctx)).rejects.toThrow(
      ServiceUnavailableException,
    );

    expect(auditService.log).toHaveBeenCalledWith(
      "user-1",
      "indexer_lag_guard.blocked",
      "INDEXER_LAG",
      expect.any(Object),
    );
    expect(metricsService.recordIndexerLagGuardBlockedRequest).toHaveBeenCalledWith(
      "GET",
      "/transactions",
    );
  });
});