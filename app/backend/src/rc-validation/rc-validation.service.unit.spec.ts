import { Test, TestingModule } from "@nestjs/testing";

import { RcValidationService } from "./rc-validation.service";
import { AppConfigService } from "../config";
import { HealthService } from "../health/health.service";
import { ContractRegistryService } from "../contracts/contract-registry.service";
import { IndexerLagService } from "../indexer-lag/indexer-lag.service";
import { EnvironmentParityService } from "../environment-parity/environment-parity.service";

describe("RcValidationService", () => {
  let service: RcValidationService;
  let mockConfig: Partial<AppConfigService>;
  let mockHealth: { getReadinessStatus: jest.Mock };
  let mockRegistry: { getRegistry: jest.Mock };
  let mockIndexerLag: { getStatus: jest.Mock; isBlocked: jest.Mock };
  let mockParity: { getResults: jest.Mock };

  // Healthy defaults — each test overrides only what it needs.
  const healthyReadiness = () => ({
    ready: true,
    timestamp: new Date().toISOString(),
    checks: [
      { name: "supabase", status: "up" as const },
      { name: "migrations", status: "up" as const },
      { name: "queue", status: "up" as const },
      { name: "horizon", status: "up" as const },
    ],
  });

  const healthyRegistry = () => ({
    network: "testnet",
    authoritative: true,
    version: 3,
    etag: 'W/"contract-registry-testnet-3"',
    data: { quickex: { id: "C123", wasmHash: "abc", version: 1 } },
  });

  const healthyLag = () => ({
    currentNetworkLedger: 1000,
    lastIndexedLedger: 998,
    lagLedgers: 2,
    isLagging: false,
    isEnabled: true,
    isOverridden: false,
    thresholdLedgers: 100,
  });

  const healthyParity = () => [
    { check: "network_configuration", status: "pass" as const, details: "ok" },
    { check: "supabase_configuration", status: "pass" as const },
  ];

  beforeEach(async () => {
    mockConfig = {
      network: "testnet",
      environmentName: "staging",
      nodeEnv: "test",
    };
    mockHealth = { getReadinessStatus: jest.fn().mockResolvedValue(healthyReadiness()) };
    mockRegistry = { getRegistry: jest.fn().mockResolvedValue(healthyRegistry()) };
    mockIndexerLag = {
      getStatus: jest.fn().mockReturnValue(healthyLag()),
      isBlocked: jest.fn().mockReturnValue(false),
    };
    mockParity = { getResults: jest.fn().mockReturnValue(healthyParity()) };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        RcValidationService,
        { provide: AppConfigService, useValue: mockConfig },
        { provide: HealthService, useValue: mockHealth },
        { provide: ContractRegistryService, useValue: mockRegistry },
        { provide: IndexerLagService, useValue: mockIndexerLag },
        { provide: EnvironmentParityService, useValue: mockParity },
      ],
    }).compile();

    service = module.get<RcValidationService>(RcValidationService);
  });

  it("should be defined", () => {
    expect(service).toBeDefined();
  });

  describe("complete (healthy) report", () => {
    it("returns a ready report with no blockers", async () => {
      const report = await service.generateReport();

      expect(report.releaseReady).toBe(true);
      expect(report.overallStatus).toBe("ready");
      expect(report.blockers).toHaveLength(0);
      expect(report.summary).toEqual({ critical: 0, warning: 0, info: 0 });

      expect(report.sections.smoke.status).toBe("pass");
      expect(report.sections.registry.status).toBe("pass");
      expect(report.sections.lag.status).toBe("pass");
      expect(report.sections.environment.status).toBe("pass");
    });

    it("is timestamped and uniquely identified (reproducible/auditable)", async () => {
      const first = await service.generateReport();
      const second = await service.generateReport();

      expect(first.reportId).not.toEqual(second.reportId);
      expect(new Date(first.generatedAt).toString()).not.toBe("Invalid Date");
      expect(first.network).toBe("testnet");
      expect(first.environment).toBe("staging");
      // All blockers share the report's generation timestamp.
      const blocky = await (async () => {
        mockIndexerLag.isBlocked.mockReturnValue(true);
        return service.generateReport();
      })();
      expect(blocky.blockers[0].detectedAt).toBe(blocky.generatedAt);
    });
  });

  describe("degraded report", () => {
    it("classifies a non-blocking lag as a warning and stays release-ready", async () => {
      mockIndexerLag.getStatus.mockReturnValue({
        ...healthyLag(),
        lagLedgers: 250,
        isLagging: true,
      });
      mockIndexerLag.isBlocked.mockReturnValue(false); // guard overridden/disabled

      const report = await service.generateReport();

      expect(report.overallStatus).toBe("degraded");
      expect(report.releaseReady).toBe(true);
      expect(report.summary.critical).toBe(0);
      expect(report.summary.warning).toBe(1);

      const lagBlocker = report.blockers.find((b) => b.category === "lag");
      expect(lagBlocker?.severity).toBe("warning");
      expect(lagBlocker?.detectedAt).toBe(report.generatedAt);
    });

    it("classifies environment parity warnings as info-level blockers", async () => {
      mockParity.getResults.mockReturnValue([
        ...healthyParity(),
        { check: "feature_flags", status: "warning", details: "none set" },
      ]);

      const report = await service.generateReport();

      expect(report.overallStatus).toBe("degraded");
      expect(report.releaseReady).toBe(true);
      expect(report.summary.info).toBe(1);
      expect(report.sections.environment.status).toBe("warning");
      const envBlocker = report.blockers.find((b) => b.category === "environment");
      expect(envBlocker?.severity).toBe("info");
    });
  });

  describe("blocked report", () => {
    it("flags a failed smoke check as a critical blocker", async () => {
      mockHealth.getReadinessStatus.mockResolvedValue({
        ready: false,
        timestamp: new Date().toISOString(),
        checks: [
          { name: "supabase", status: "up" },
          { name: "horizon", status: "down", error: "Horizon returned 503" },
        ],
      });

      const report = await service.generateReport();

      expect(report.overallStatus).toBe("blocked");
      expect(report.releaseReady).toBe(false);
      expect(report.summary.critical).toBe(1);
      const smokeBlocker = report.blockers.find((b) => b.category === "smoke");
      expect(smokeBlocker?.severity).toBe("critical");
      expect(smokeBlocker?.message).toContain("horizon");
      expect(report.sections.smoke.failed).toBe(1);
    });

    it("flags missing expected contracts as a critical blocker", async () => {
      mockRegistry.getRegistry.mockResolvedValue({
        ...healthyRegistry(),
        data: {}, // quickex missing
      });

      const report = await service.generateReport();

      expect(report.releaseReady).toBe(false);
      expect(report.sections.registry.status).toBe("fail");
      expect(report.sections.registry.missingContracts).toContain("quickex");
      const regBlocker = report.blockers.find((b) => b.category === "registry");
      expect(regBlocker?.severity).toBe("critical");
    });

    it("flags a blocking indexer lag as critical", async () => {
      mockIndexerLag.getStatus.mockReturnValue({
        ...healthyLag(),
        lagLedgers: 500,
        isLagging: true,
      });
      mockIndexerLag.isBlocked.mockReturnValue(true);

      const report = await service.generateReport();

      expect(report.overallStatus).toBe("blocked");
      expect(report.sections.lag.status).toBe("fail");
      expect(report.sections.lag.isBlocking).toBe(true);
      const lagBlocker = report.blockers.find((b) => b.category === "lag");
      expect(lagBlocker?.severity).toBe("critical");
    });
  });

  describe("partial report (degraded sources)", () => {
    it("still produces a report when the registry source throws", async () => {
      mockRegistry.getRegistry.mockRejectedValue(new Error("supabase down"));

      const report = await service.generateReport();

      // Other sections still evaluated.
      expect(report.sections.smoke.status).toBe("pass");
      expect(report.sections.lag.status).toBe("pass");
      // Failed source surfaced as unknown + critical blocker.
      expect(report.sections.registry.status).toBe("unknown");
      const regBlocker = report.blockers.find(
        (b) => b.id === "registry.unavailable",
      );
      expect(regBlocker?.severity).toBe("critical");
      expect(report.releaseReady).toBe(false);
    });

    it("treats a missing lag computation as an info-level advisory", async () => {
      mockIndexerLag.getStatus.mockReturnValue({
        ...healthyLag(),
        currentNetworkLedger: null,
        lastIndexedLedger: null,
        lagLedgers: null,
      });

      const report = await service.generateReport();

      expect(report.sections.lag.status).toBe("warning");
      const lagBlocker = report.blockers.find((b) => b.id === "lag.unknown");
      expect(lagBlocker?.severity).toBe("info");
      expect(report.releaseReady).toBe(true);
    });

    it("aggregates multiple blocker severities into the summary counts", async () => {
      mockHealth.getReadinessStatus.mockResolvedValue({
        ready: false,
        timestamp: new Date().toISOString(),
        checks: [{ name: "queue", status: "down", error: "timeout" }],
      });
      mockIndexerLag.getStatus.mockReturnValue({
        ...healthyLag(),
        lagLedgers: 250,
        isLagging: true,
      });
      mockParity.getResults.mockReturnValue([
        { check: "feature_flags", status: "warning", details: "none" },
      ]);

      const report = await service.generateReport();

      expect(report.summary.critical).toBe(1); // smoke
      expect(report.summary.warning).toBe(1); // lag
      expect(report.summary.info).toBe(1); // environment
      expect(report.overallStatus).toBe("blocked");
    });
  });
});
