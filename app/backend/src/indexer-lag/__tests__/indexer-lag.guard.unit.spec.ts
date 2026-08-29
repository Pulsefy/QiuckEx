import { ExecutionContext, ServiceUnavailableException } from "@nestjs/common";
import { Reflector } from "@nestjs/core";

import { AuditService } from "../../audit/audit.service";
import { MetricsService } from "../../metrics/metrics.service";
import { IndexerLagGuard } from "../indexer-lag.guard";
import { IndexerLagService } from "../indexer-lag.service";
import { REQUIRE_INDEXER_LAG_CHECK_KEY } from "../requires-indexer-lag-check.decorator";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeExecutionContext(
  requiresCheck: boolean | undefined,
  opts: { method?: string; path?: string; userId?: string } = {},
): ExecutionContext {
  const { method = "POST", path = "/contracts/build", userId } = opts;
  const headers: Record<string, string> = {};
  if (userId) headers["x-user-id"] = userId;

  return {
    getHandler: jest.fn(),
    getClass: jest.fn(),
    switchToHttp: jest.fn().mockReturnValue({
      getRequest: jest.fn().mockReturnValue({
        method,
        path,
        route: { path },
        headers,
      }),
    }),
  } as unknown as ExecutionContext;
}

function buildGuard(overrides: {
  requiresCheck?: boolean;
  isBlocked?: boolean;
  status?: {
    currentNetworkLedger?: number | null;
    lastIndexedLedger?: number | null;
    lagLedgers?: number | null;
    thresholdLedgers?: number;
  };
}) {
  const {
    requiresCheck = true,
    isBlocked = false,
    status = {
      currentNetworkLedger: 1000,
      lastIndexedLedger: 900,
      lagLedgers: 100,
      thresholdLedgers: 100,
    },
  } = overrides;

  const reflector = {
    getAllAndOverride: jest
      .fn()
      .mockReturnValue(requiresCheck ? true : undefined),
  } as unknown as Reflector;

  const indexerLagService = {
    isBlocked: jest.fn().mockReturnValue(isBlocked),
    getStatus: jest.fn().mockReturnValue(status),
  } as unknown as IndexerLagService;

  const auditService = {
    log: jest.fn().mockResolvedValue(undefined),
  } as unknown as AuditService;

  const metricsService = {
    recordIndexerLagGuardBlockedRequest: jest.fn(),
  } as unknown as MetricsService;

  const guard = new IndexerLagGuard(
    reflector,
    indexerLagService,
    auditService,
    metricsService,
  );

  return { guard, reflector, indexerLagService, auditService, metricsService };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("IndexerLagGuard", () => {
  // ── Decorator absent ──────────────────────────────────────────────────────

  it("should allow the request when @RequiresIndexerLagCheck is not present", async () => {
    const { guard } = buildGuard({ requiresCheck: false });
    const ctx = makeExecutionContext(false);

    await expect(guard.canActivate(ctx)).resolves.toBe(true);
  });

  // ── Not blocked ───────────────────────────────────────────────────────────

  it("should allow the request when decorator is present but indexer is not lagging", async () => {
    const { guard } = buildGuard({ requiresCheck: true, isBlocked: false });
    const ctx = makeExecutionContext(true);

    await expect(guard.canActivate(ctx)).resolves.toBe(true);
  });

  // ── Blocked ───────────────────────────────────────────────────────────────

  it("should throw ServiceUnavailableException when indexer is lagging", async () => {
    const { guard } = buildGuard({ requiresCheck: true, isBlocked: true });
    const ctx = makeExecutionContext(true);

    await expect(guard.canActivate(ctx)).rejects.toBeInstanceOf(
      ServiceUnavailableException,
    );
  });

  it("should include lag details in the ServiceUnavailableException response", async () => {
    const lagStatus = {
      currentNetworkLedger: 1000,
      lastIndexedLedger: 500,
      lagLedgers: 500,
      thresholdLedgers: 100,
    };
    const { guard } = buildGuard({
      requiresCheck: true,
      isBlocked: true,
      status: lagStatus,
    });
    const ctx = makeExecutionContext(true);

    try {
      await guard.canActivate(ctx);
      fail("Expected ServiceUnavailableException to be thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(ServiceUnavailableException);
      const response = (err as ServiceUnavailableException).getResponse() as {
        details: typeof lagStatus;
      };
      expect(response.details.lagLedgers).toBe(500);
      expect(response.details.currentNetworkLedger).toBe(1000);
      expect(response.details.lastIndexedLedger).toBe(500);
      expect(response.details.thresholdLedgers).toBe(100);
    }
  });

  // ── Side effects when blocked ──────────────────────────────────────────────

  it("should record a blocked request metric when lagging", async () => {
    const { guard, metricsService } = buildGuard({
      requiresCheck: true,
      isBlocked: true,
    });
    const ctx = makeExecutionContext(true, {
      method: "POST",
      path: "/contracts/build",
    });

    await expect(guard.canActivate(ctx)).rejects.toBeInstanceOf(
      ServiceUnavailableException,
    );

    expect(
      metricsService.recordIndexerLagGuardBlockedRequest,
    ).toHaveBeenCalledWith("POST", "/contracts/build");
  });

  it("should log an audit event when lagging", async () => {
    const { guard, auditService } = buildGuard({
      requiresCheck: true,
      isBlocked: true,
    });
    const ctx = makeExecutionContext(true, {
      method: "POST",
      path: "/contracts/build",
      userId: "user-42",
    });

    await expect(guard.canActivate(ctx)).rejects.toBeInstanceOf(
      ServiceUnavailableException,
    );

    expect(auditService.log).toHaveBeenCalledWith(
      "user-42",
      "indexer_lag_guard.blocked",
      "INDEXER_LAG",
      expect.objectContaining({ method: "POST", path: "/contracts/build" }),
    );
  });

  it("should use 'anonymous' actor in audit log when no x-user-id header is present", async () => {
    const { guard, auditService } = buildGuard({
      requiresCheck: true,
      isBlocked: true,
    });
    const ctx = makeExecutionContext(true, {
      method: "POST",
      path: "/contracts/build",
    });

    await expect(guard.canActivate(ctx)).rejects.toBeInstanceOf(
      ServiceUnavailableException,
    );

    expect(auditService.log).toHaveBeenCalledWith(
      "anonymous",
      expect.any(String),
      expect.any(String),
      expect.any(Object),
    );
  });

  // ── Reflector key check ────────────────────────────────────────────────────

  it("should check both handler and class for the @RequiresIndexerLagCheck key", async () => {
    const { guard, reflector } = buildGuard({
      requiresCheck: false,
      isBlocked: false,
    });
    const ctx = makeExecutionContext(false);

    await guard.canActivate(ctx);

    expect(reflector.getAllAndOverride).toHaveBeenCalledWith(
      REQUIRE_INDEXER_LAG_CHECK_KEY,
      expect.arrayContaining([expect.any(Function), expect.any(Function)]),
    );
  });
});
