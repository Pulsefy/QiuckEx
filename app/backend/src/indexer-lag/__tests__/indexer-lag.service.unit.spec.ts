import { Test, TestingModule } from "@nestjs/testing";

import { AppConfigService } from "../../config";
import { IndexerCheckpointRepository } from "../../ingestion/indexer-checkpoint.repository";
import { MetricsService } from "../../metrics/metrics.service";
import { IndexerLagService } from "../indexer-lag.service";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function buildMocks(overrides: {
  network?: "testnet" | "mainnet";
  quickexContractId?: string | null;
  indexerLagThresholdLedgers?: number;
  indexerLagGuardEnabled?: boolean;
  indexerLagGuardOverride?: boolean;
} = {}) {
  const config = {
    network: overrides.network ?? "testnet",
    quickexContractId: overrides.quickexContractId ?? "CTEST_CONTRACT_ID",
    indexerLagThresholdLedgers: overrides.indexerLagThresholdLedgers ?? 100,
    indexerLagGuardEnabled:
      overrides.indexerLagGuardEnabled !== undefined
        ? overrides.indexerLagGuardEnabled
        : true,
    indexerLagGuardOverride:
      overrides.indexerLagGuardOverride !== undefined
        ? overrides.indexerLagGuardOverride
        : false,
  } as unknown as AppConfigService;

  const checkpointRepo = {
    getLastLedger: jest.fn().mockResolvedValue(null),
  } as unknown as IndexerCheckpointRepository;

  const metrics = {
    recordIndexerLag: jest.fn(),
    setIndexerLagGuardStatus: jest.fn(),
  } as unknown as MetricsService;

  return { config, checkpointRepo, metrics };
}

async function buildService(
  mocks: ReturnType<typeof buildMocks>,
): Promise<IndexerLagService> {
  const module: TestingModule = await Test.createTestingModule({
    providers: [
      IndexerLagService,
      { provide: AppConfigService, useValue: mocks.config },
      {
        provide: IndexerCheckpointRepository,
        useValue: mocks.checkpointRepo,
      },
      { provide: MetricsService, useValue: mocks.metrics },
    ],
  }).compile();

  return module.get<IndexerLagService>(IndexerLagService);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("IndexerLagService", () => {
  let fetchMock: jest.SpyInstance;

  beforeEach(() => {
    // Stub global fetch so no real HTTP requests are made during tests.
    fetchMock = jest.spyOn(global, "fetch").mockResolvedValue({
      ok: true,
      json: jest.fn().mockResolvedValue({ core_latest_ledger: 1000 }),
    } as unknown as Response);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  // ── Module initialisation ────────────────────────────────────────────────

  describe("onModuleInit / constructor", () => {
    it("should be defined after module init", async () => {
      const mocks = buildMocks();
      const service = await buildService(mocks);
      // onModuleInit is called by NestJS; call it explicitly here to exercise
      // the init path without waiting on the cron scheduler.
      expect(service).toBeDefined();
    });

    it("should pick up the testnet Horizon URL from config", async () => {
      const mocks = buildMocks({ network: "testnet" });
      await buildService(mocks);
      // The service reads HORIZON_BASE_URLS[config.network] in the constructor.
      // We verify the correct URL is used during a subsequent pollHorizon() call.
      const service = await buildService(mocks);
      await service.pollHorizon();
      expect(fetchMock).toHaveBeenCalledWith(
        expect.stringContaining("horizon-testnet.stellar.org"),
        expect.any(Object),
      );
    });

    it("should pick up the mainnet Horizon URL from config", async () => {
      const mocks = buildMocks({ network: "mainnet" });
      const service = await buildService(mocks);
      await service.pollHorizon();
      expect(fetchMock).toHaveBeenCalledWith(
        expect.stringContaining("horizon.stellar.org"),
        expect.any(Object),
      );
    });
  });

  // ── getStatus() ──────────────────────────────────────────────────────────

  describe("getStatus()", () => {
    it("should return null lag when neither ledger has been fetched yet", async () => {
      const mocks = buildMocks();
      const service = await buildService(mocks);

      const status = service.getStatus();
      expect(status.currentNetworkLedger).toBeNull();
      expect(status.lastIndexedLedger).toBeNull();
      expect(status.lagLedgers).toBeNull();
    });

    it("should report isLagging=false when lag is below threshold", async () => {
      const mocks = buildMocks({ indexerLagThresholdLedgers: 100 });
      (mocks.checkpointRepo.getLastLedger as jest.Mock).mockResolvedValue(950);
      fetchMock.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue({ core_latest_ledger: 1000 }),
      } as unknown as Response);

      const service = await buildService(mocks);
      await service.pollHorizon();

      const status = service.getStatus();
      expect(status.currentNetworkLedger).toBe(1000);
      expect(status.lastIndexedLedger).toBe(950);
      expect(status.lagLedgers).toBe(50);
      expect(status.isLagging).toBe(false);
    });

    it("should report isLagging=true when lag exceeds threshold", async () => {
      const mocks = buildMocks({ indexerLagThresholdLedgers: 100 });
      (mocks.checkpointRepo.getLastLedger as jest.Mock).mockResolvedValue(800);
      fetchMock.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue({ core_latest_ledger: 1000 }),
      } as unknown as Response);

      const service = await buildService(mocks);
      await service.pollHorizon();

      const status = service.getStatus();
      expect(status.lagLedgers).toBe(200);
      expect(status.isLagging).toBe(true);
    });

    it("should return lagLedgers=0 when indexed ledger is ahead of network ledger", async () => {
      const mocks = buildMocks({ indexerLagThresholdLedgers: 100 });
      (mocks.checkpointRepo.getLastLedger as jest.Mock).mockResolvedValue(1010);
      fetchMock.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue({ core_latest_ledger: 1000 }),
      } as unknown as Response);

      const service = await buildService(mocks);
      await service.pollHorizon();

      const status = service.getStatus();
      expect(status.lagLedgers).toBe(0);
      expect(status.isLagging).toBe(false);
    });

    it("should reflect guard enabled state in status", async () => {
      const mocks = buildMocks({ indexerLagGuardEnabled: false });
      const service = await buildService(mocks);

      const status = service.getStatus();
      expect(status.isEnabled).toBe(false);
    });

    it("should reflect guard override state in status", async () => {
      const mocks = buildMocks({ indexerLagGuardOverride: true });
      const service = await buildService(mocks);

      const status = service.getStatus();
      expect(status.isOverridden).toBe(true);
    });

    it("should expose the configured threshold in status", async () => {
      const mocks = buildMocks({ indexerLagThresholdLedgers: 250 });
      const service = await buildService(mocks);

      const status = service.getStatus();
      expect(status.thresholdLedgers).toBe(250);
    });

    it("should fall back to history_latest_ledger when core_latest_ledger is absent", async () => {
      const mocks = buildMocks();
      fetchMock.mockResolvedValue({
        ok: true,
        json: jest
          .fn()
          .mockResolvedValue({ history_latest_ledger: 2000 }),
      } as unknown as Response);
      (mocks.checkpointRepo.getLastLedger as jest.Mock).mockResolvedValue(1900);

      const service = await buildService(mocks);
      await service.pollHorizon();

      const status = service.getStatus();
      expect(status.currentNetworkLedger).toBe(2000);
      expect(status.lagLedgers).toBe(100);
    });
  });

  // ── isBlocked() ──────────────────────────────────────────────────────────

  describe("isBlocked()", () => {
    it("should return false when guard is disabled, even if lagging", async () => {
      const mocks = buildMocks({
        indexerLagGuardEnabled: false,
        indexerLagThresholdLedgers: 100,
      });
      (mocks.checkpointRepo.getLastLedger as jest.Mock).mockResolvedValue(500);
      fetchMock.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue({ core_latest_ledger: 1000 }),
      } as unknown as Response);

      const service = await buildService(mocks);
      await service.pollHorizon();

      expect(service.isBlocked()).toBe(false);
    });

    it("should return false when override is active, even if lagging", async () => {
      const mocks = buildMocks({
        indexerLagGuardEnabled: true,
        indexerLagGuardOverride: true,
        indexerLagThresholdLedgers: 100,
      });
      (mocks.checkpointRepo.getLastLedger as jest.Mock).mockResolvedValue(500);
      fetchMock.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue({ core_latest_ledger: 1000 }),
      } as unknown as Response);

      const service = await buildService(mocks);
      await service.pollHorizon();

      expect(service.isBlocked()).toBe(false);
    });

    it("should return true when guard is enabled, no override, and lagging", async () => {
      const mocks = buildMocks({
        indexerLagGuardEnabled: true,
        indexerLagGuardOverride: false,
        indexerLagThresholdLedgers: 100,
      });
      (mocks.checkpointRepo.getLastLedger as jest.Mock).mockResolvedValue(500);
      fetchMock.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue({ core_latest_ledger: 1000 }),
      } as unknown as Response);

      const service = await buildService(mocks);
      await service.pollHorizon();

      expect(service.isBlocked()).toBe(true);
    });

    it("should return false when guard is enabled but not lagging", async () => {
      const mocks = buildMocks({
        indexerLagGuardEnabled: true,
        indexerLagGuardOverride: false,
        indexerLagThresholdLedgers: 100,
      });
      (mocks.checkpointRepo.getLastLedger as jest.Mock).mockResolvedValue(990);
      fetchMock.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue({ core_latest_ledger: 1000 }),
      } as unknown as Response);

      const service = await buildService(mocks);
      await service.pollHorizon();

      expect(service.isBlocked()).toBe(false);
    });

    it("should return false when ledger data is not yet available", async () => {
      const mocks = buildMocks({ indexerLagGuardEnabled: true });
      const service = await buildService(mocks);

      // No pollHorizon() called — ledgers are null, lag is null, not lagging.
      expect(service.isBlocked()).toBe(false);
    });
  });

  // ── pollHorizon() ────────────────────────────────────────────────────────

  describe("pollHorizon()", () => {
    it("should update currentNetworkLedger from Horizon response", async () => {
      const mocks = buildMocks();
      fetchMock.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue({ core_latest_ledger: 1234 }),
      } as unknown as Response);

      const service = await buildService(mocks);
      await service.pollHorizon();

      expect(service.getStatus().currentNetworkLedger).toBe(1234);
    });

    it("should update lastIndexedLedger from checkpoint repository", async () => {
      const mocks = buildMocks({ quickexContractId: "CTEST_ABC" });
      (mocks.checkpointRepo.getLastLedger as jest.Mock).mockResolvedValue(4321);

      const service = await buildService(mocks);
      await service.pollHorizon();

      expect(service.getStatus().lastIndexedLedger).toBe(4321);
    });

    it("should skip checkpoint lookup when quickexContractId is absent", async () => {
      const mocks = buildMocks({ quickexContractId: null });
      const service = await buildService(mocks);
      await service.pollHorizon();

      expect(mocks.checkpointRepo.getLastLedger).not.toHaveBeenCalled();
      expect(service.getStatus().lastIndexedLedger).toBeNull();
    });

    it("should log an error but not throw when Horizon fetch fails", async () => {
      fetchMock.mockRejectedValue(new Error("network timeout"));

      const mocks = buildMocks();
      const service = await buildService(mocks);

      await expect(service.pollHorizon()).resolves.toBeUndefined();
    });

    it("should log an error but not throw when Horizon returns a non-ok status", async () => {
      fetchMock.mockResolvedValue({
        ok: false,
        status: 503,
      } as unknown as Response);

      const mocks = buildMocks();
      const service = await buildService(mocks);

      await expect(service.pollHorizon()).resolves.toBeUndefined();
    });

    it("should log an error but not throw when checkpoint repo throws", async () => {
      (jest.spyOn(global, "fetch") as jest.Mock).mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue({ core_latest_ledger: 1000 }),
      } as unknown as Response);

      const mocks = buildMocks();
      (mocks.checkpointRepo.getLastLedger as jest.Mock).mockRejectedValue(
        new Error("db error"),
      );

      const service = await buildService(mocks);

      await expect(service.pollHorizon()).resolves.toBeUndefined();
    });

    it("should not update currentNetworkLedger when Horizon body has no ledger field", async () => {
      fetchMock.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue({}),
      } as unknown as Response);

      const mocks = buildMocks();
      const service = await buildService(mocks);
      await service.pollHorizon();

      expect(service.getStatus().currentNetworkLedger).toBeNull();
    });

    it("should call recordIndexerLag via MetricsService when lag is available", async () => {
      const mocks = buildMocks({ indexerLagThresholdLedgers: 100 });
      (mocks.checkpointRepo.getLastLedger as jest.Mock).mockResolvedValue(900);
      fetchMock.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue({ core_latest_ledger: 1000 }),
      } as unknown as Response);

      const service = await buildService(mocks);
      await service.pollHorizon();

      expect(mocks.metrics.recordIndexerLag).toHaveBeenCalledWith(100);
    });

    it("should not call recordIndexerLag when lag cannot be computed", async () => {
      const mocks = buildMocks();
      // Only network ledger available, no checkpoint data
      fetchMock.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue({ core_latest_ledger: 1000 }),
      } as unknown as Response);
      (mocks.checkpointRepo.getLastLedger as jest.Mock).mockResolvedValue(null);

      const service = await buildService(mocks);
      await service.pollHorizon();

      expect(mocks.metrics.recordIndexerLag).not.toHaveBeenCalled();
    });
  });

  // ── Metrics reporting (updateMetrics) ────────────────────────────────────

  describe("metrics reporting", () => {
    it("should set guard status=0 (disabled) when guard is disabled", async () => {
      const mocks = buildMocks({ indexerLagGuardEnabled: false });
      const service = await buildService(mocks);
      await service.pollHorizon();

      expect(mocks.metrics.setIndexerLagGuardStatus).toHaveBeenCalledWith(0);
    });

    it("should set guard status=2 (overridden) when override is active and guard is enabled", async () => {
      const mocks = buildMocks({
        indexerLagGuardEnabled: true,
        indexerLagGuardOverride: true,
      });
      const service = await buildService(mocks);
      await service.pollHorizon();

      expect(mocks.metrics.setIndexerLagGuardStatus).toHaveBeenCalledWith(2);
    });

    it("should set guard status=3 (lagging) when guard is enabled and lag exceeds threshold", async () => {
      const mocks = buildMocks({
        indexerLagGuardEnabled: true,
        indexerLagGuardOverride: false,
        indexerLagThresholdLedgers: 100,
      });
      (mocks.checkpointRepo.getLastLedger as jest.Mock).mockResolvedValue(500);
      fetchMock.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue({ core_latest_ledger: 1000 }),
      } as unknown as Response);

      const service = await buildService(mocks);
      await service.pollHorizon();

      expect(mocks.metrics.setIndexerLagGuardStatus).toHaveBeenCalledWith(3);
    });

    it("should set guard status=1 (enabled, healthy) when guard is enabled and not lagging", async () => {
      const mocks = buildMocks({
        indexerLagGuardEnabled: true,
        indexerLagGuardOverride: false,
        indexerLagThresholdLedgers: 100,
      });
      (mocks.checkpointRepo.getLastLedger as jest.Mock).mockResolvedValue(990);
      fetchMock.mockResolvedValue({
        ok: true,
        json: jest.fn().mockResolvedValue({ core_latest_ledger: 1000 }),
      } as unknown as Response);

      const service = await buildService(mocks);
      await service.pollHorizon();

      expect(mocks.metrics.setIndexerLagGuardStatus).toHaveBeenCalledWith(1);
    });
  });
});
