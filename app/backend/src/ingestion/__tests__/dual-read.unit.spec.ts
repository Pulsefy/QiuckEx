/* eslint-disable @typescript-eslint/no-explicit-any */
import { Test, TestingModule } from "@nestjs/testing";
import { SorobanEventIndexerService, DualReadConfig } from "../soroban-event-indexer.service";
import { IndexerCheckpointRepository } from "../indexer-checkpoint.repository";
import { EscrowEventRepository } from "../escrow-event.repository";
import { PrivacyEventRepository } from "../privacy-event.repository";
import { AdminEventRepository } from "../admin-event.repository";
import { StealthEventRepository } from "../stealth-event.repository";
import { MetricsService } from "../../metrics/metrics.service";
import { EventEmitter2 } from "@nestjs/event-emitter";
import { AppConfigService } from "../../config";

describe("SorobanEventIndexerService - Dual-Read", () => {
  let service: SorobanEventIndexerService;
  let checkpointRepo: jest.Mocked<IndexerCheckpointRepository>;

  beforeEach(async () => {
    const mockCheckpointRepo = {
      getLastLedger: jest.fn().mockResolvedValue(null),
      saveLastLedger: jest.fn().mockResolvedValue(undefined),
    };

    const mockEscrowRepo = {
      upsertEvent: jest.fn().mockResolvedValue(undefined),
    };

    const mockPrivacyRepo = {
      upsertEvent: jest.fn().mockResolvedValue(undefined),
    };

    const mockAdminRepo = {
      upsertEvent: jest.fn().mockResolvedValue(undefined),
    };

    const mockStealthRepo = {
      upsertEvent: jest.fn().mockResolvedValue(undefined),
    };

    const mockMetrics = {
      recordUnknownSchemaVersion: jest.fn(),
    };

    const mockEventEmitter = {
      emit: jest.fn(),
    };

    const mockConfigService = {
      network: "testnet",
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        SorobanEventIndexerService,
        { provide: IndexerCheckpointRepository, useValue: mockCheckpointRepo },
        { provide: EscrowEventRepository, useValue: mockEscrowRepo },
        { provide: PrivacyEventRepository, useValue: mockPrivacyRepo },
        { provide: AdminEventRepository, useValue: mockAdminRepo },
        { provide: StealthEventRepository, useValue: mockStealthRepo },
        { provide: MetricsService, useValue: mockMetrics },
        { provide: EventEmitter2, useValue: mockEventEmitter },
        { provide: AppConfigService, useValue: mockConfigService },
      ],
    }).compile();

    service = module.get<SorobanEventIndexerService>(SorobanEventIndexerService);
    checkpointRepo = module.get(IndexerCheckpointRepository) as jest.Mocked<IndexerCheckpointRepository>;
  });

  describe("Dual-read window detection", () => {
    it("should detect when in dual-read window (before effective ledger)", () => {
      const config: DualReadConfig = {
        previousContractId: "CPREV",
        effectiveLedger: 50_000_000,
        effectiveTime: new Date("2026-06-02T12:00:00Z"),
      };

      expect((service as any).isInDualReadWindow(40_000_000, config)).toBe(true);
    });

    it("should detect when past dual-read window (at or after effective ledger)", () => {
      const config: DualReadConfig = {
        previousContractId: "CPREV",
        effectiveLedger: 50_000_000,
        effectiveTime: new Date("2026-06-02T12:00:00Z"),
      };

      expect((service as any).isInDualReadWindow(50_000_000, config)).toBe(false);
      expect((service as any).isInDualReadWindow(60_000_000, config)).toBe(false);
    });

    it("should not be in dual-read window if no previous contract ID", () => {
      const config: DualReadConfig = {
        previousContractId: undefined,
        effectiveLedger: 50_000_000,
      };

      expect((service as any).isInDualReadWindow(40_000_000, config)).toBe(false);
    });

    it("should not be in dual-read window if no effective ledger", () => {
      const config: DualReadConfig = {
        previousContractId: "CPREV",
        effectiveLedger: undefined,
      };

      expect((service as any).isInDualReadWindow(40_000_000, config)).toBe(false);
    });
  });

  describe("Checkpoint isolation", () => {
    it("should maintain separate checkpoints for current and previous contract IDs", async () => {
      const currentId = "CCUR";
      const previousId = "CPREV";
      const config: DualReadConfig = {
        previousContractId: previousId,
        effectiveLedger: 50_000_000,
      };

      jest.spyOn(service as any, "fetchPage").mockResolvedValue({ records: [], nextCursor: undefined });

      await service.indexLedgerRange(currentId, 1000, 2000, config);

      expect(checkpointRepo.saveLastLedger).toHaveBeenCalledWith(previousId, 2000);
      expect(checkpointRepo.saveLastLedger).toHaveBeenCalledWith(currentId, 2000);
    });
  });

  describe("Dual-read range validation", () => {
    it("should not index if range is already indexed (before effective ledger)", async () => {
      const currentId = "CCUR";
      const config: DualReadConfig = {
        previousContractId: "CPREV",
        effectiveLedger: 50_000_000,
      };

      checkpointRepo.getLastLedger.mockResolvedValue(5000);

      const result = await service.indexLedgerRange(currentId, 1000, 2000, config);

      expect(result.processed).toBe(0);
      expect(result.persisted).toBe(0);
    });

    it("should index from checkpoint when resuming (dual-read)", async () => {
      const currentId = "CCUR";
      const config: DualReadConfig = {
        previousContractId: "CPREV",
        effectiveLedger: 50_000_000,
      };

      checkpointRepo.getLastLedger.mockResolvedValueOnce(1500).mockResolvedValueOnce(null);

      jest.spyOn(service as any, "fetchPage").mockResolvedValue({ records: [], nextCursor: undefined });

      await service.indexLedgerRange(currentId, 1000, 2000, config);

      const calls = (service as any).fetchPage.mock.calls;
      expect(calls[0][1]).toBe(1501);
      expect(calls[1][1]).toBe(1501);
    });
  });

  describe("Force reindex with dual-read", () => {
    it("should reindex full range when force=true even with checkpoint", async () => {
      const currentId = "CCUR";
      const config: DualReadConfig = {
        previousContractId: "CPREV",
        effectiveLedger: 50_000_000,
      };

      checkpointRepo.getLastLedger.mockResolvedValue(1500);

      jest.spyOn(service as any, "fetchPage").mockResolvedValue({ records: [], nextCursor: undefined });

      await service.indexLedgerRange(currentId, 1000, 2000, config, true);

      const calls = (service as any).fetchPage.mock.calls;
      expect(calls[0][1]).toBe(1000);
      expect(calls[1][1]).toBe(1000);
    });
  });

  describe("Effective ledger boundary", () => {
    it("should index previous contract only up to effective ledger", async () => {
      const currentId = "CCUR";
      const previousId = "CPREV";
      const effectiveLedger = 50_000_000;
      const config: DualReadConfig = {
        previousContractId: previousId,
        effectiveLedger,
      };

      jest.spyOn(service as any, "fetchPage").mockResolvedValue({ records: [], nextCursor: undefined });

      await service.indexLedgerRange(currentId, 1000, 100_000_000, config);

      const previousCalls = (service as any).fetchPage.mock.calls.filter(
        (call: unknown[]) => call[0] === previousId,
      );
      const currentCalls = (service as any).fetchPage.mock.calls.filter(
        (call: unknown[]) => call[0] === currentId,
      );

      expect(previousCalls.length).toBeGreaterThan(0);
      expect(currentCalls.length).toBeGreaterThan(0);

      if (previousCalls.length > 0) {
        expect(previousCalls[0][2]).toBe(effectiveLedger);
      }

      if (currentCalls.length > 0) {
        expect(currentCalls[0][2]).toBe(100_000_000);
      }
    });
  });

  describe("Single-read (no dual-read)", () => {
    it("should only index current contract when no dual-read config", async () => {
      const currentId = "CCUR";

      jest.spyOn(service as any, "fetchPage").mockResolvedValue({ records: [], nextCursor: undefined });

      await service.indexLedgerRange(currentId, 1000, 2000);

      const calls = (service as any).fetchPage.mock.calls;
      expect(calls).toHaveLength(1);
      expect(calls[0][0]).toBe(currentId);
    });

    it("should only index current contract when no previousContractId in config", async () => {
      const currentId = "CCUR";
      const config: DualReadConfig = {
        effectiveLedger: 50_000_000,
      };

      jest.spyOn(service as any, "fetchPage").mockResolvedValue({ records: [], nextCursor: undefined });

      await service.indexLedgerRange(currentId, 1000, 2000, config);

      const calls = (service as any).fetchPage.mock.calls;
      expect(calls).toHaveLength(1);
      expect(calls[0][0]).toBe(currentId);
    });
  });
});
