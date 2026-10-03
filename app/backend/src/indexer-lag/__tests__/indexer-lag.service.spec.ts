import { Test, TestingModule } from "@nestjs/testing";
import { IndexerLagService } from "../indexer-lag.service";
import { AppConfigService } from "../../config";
import { IndexerCheckpointRepository } from "../../ingestion/indexer-checkpoint.repository";
import { MetricsService } from "../../metrics/metrics.service";

describe("IndexerLagService", () => {
  let service: IndexerLagService;
  let configService: Partial<AppConfigService>;
  let checkpointRepo: Partial<IndexerCheckpointRepository>;
  let metricsService: Partial<MetricsService>;

  beforeEach(async () => {
    configService = {
      network: "testnet",
      indexerLagThresholdLedgers: 10,
      indexerLagGuardEnabled: true,
      indexerLagGuardOverride: false,
      quickexContractId: "CC123",
    };

    checkpointRepo = {
      getLastLedger: jest.fn().mockResolvedValue(100),
    };

    metricsService = {
      recordIndexerLag: jest.fn(),
      setIndexerLagGuardStatus: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        IndexerLagService,
        { provide: AppConfigService, useValue: configService },
        { provide: IndexerCheckpointRepository, useValue: checkpointRepo },
        { provide: MetricsService, useValue: metricsService },
      ],
    }).compile();

    service = module.get<IndexerLagService>(IndexerLagService);
  });

  afterEach(() => {
    jest.clearAllMocks();
    jest.restoreAllMocks();
  });

  it("should be defined", () => {
    expect(service).toBeDefined();
  });

  describe("pollHorizon & status transitions", () => {
    it("should handle horizon fetch failure gracefully without throwing", async () => {
      jest.spyOn(global, "fetch").mockRejectedValueOnce(new Error("Network error"));
      
      await expect(service.pollHorizon()).resolves.not.toThrow();
    });

    it("should compute correct status when lagging", async () => {
      jest.spyOn(global, "fetch").mockResolvedValueOnce({
        ok: true,
        json: async () => ({ core_latest_ledger: 120 }),
      } as Response);

      await service.pollHorizon();

      const status = service.getStatus();
      expect(status.currentNetworkLedger).toBe(120);
      expect(status.lastIndexedLedger).toBe(100);
      expect(status.lagLedgers).toBe(20);
      expect(status.isLagging).toBe(true);
      expect(service.isBlocked()).toBe(true);
    });

    it("should not be blocked when lag is within threshold", async () => {
      jest.spyOn(global, "fetch").mockResolvedValueOnce({
        ok: true,
        json: async () => ({ core_latest_ledger: 105 }),
      } as Response);

      await service.pollHorizon();

      const status = service.getStatus();
      expect(status.lagLedgers).toBe(5);
      expect(status.isLagging).toBe(false);
      expect(service.isBlocked()).toBe(false);
    });

    it("should respect guard enabled flag (disabled)", async () => {
      (configService as any).indexerLagGuardEnabled = false;
      jest.spyOn(global, "fetch").mockResolvedValueOnce({
        ok: true,
        json: async () => ({ core_latest_ledger: 200 }),
      } as Response);

      await service.pollHorizon();

      expect(service.isBlocked()).toBe(false);
    });

    it("should respect guard override flag", async () => {
      (configService as any).indexerLagGuardOverride = true;
      jest.spyOn(global, "fetch").mockResolvedValueOnce({
        ok: true,
        json: async () => ({ core_latest_ledger: 200 }),
      } as Response);

      await service.pollHorizon();

      expect(service.isBlocked()).toBe(false);
    });
  });
});