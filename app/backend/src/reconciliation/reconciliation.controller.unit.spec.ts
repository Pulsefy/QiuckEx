import { Test, TestingModule } from "@nestjs/testing";
import { ConflictException, NotFoundException } from "@nestjs/common";
import { ReconciliationController } from "./reconciliation.controller";
import { ReconciliationWorkerService } from "./reconciliation-worker.service";
import { BackfillService } from "./backfill.service";
import { AutoMatchService } from "./auto-match.service";
import { UnmatchedQueueRepository } from "./unmatched-queue.repository";
import { NetworkSafetyGuard } from "../feature-flags/network-safety.guard";

describe("ReconciliationController", () => {
  let controller: ReconciliationController;
  let worker: jest.Mocked<ReconciliationWorkerService>;
  let backfill: jest.Mocked<BackfillService>;
  let autoMatch: jest.Mocked<AutoMatchService>;
  let unmatchedQueue: jest.Mocked<UnmatchedQueueRepository>;

  beforeEach(async () => {
    const mockWorker = {
      running: false,
      getLastReport: jest.fn().mockReturnValue(null),
      triggerManually: jest.fn(),
    };

    const mockBackfill = {
      startBackfill: jest.fn(),
      getBackfillProgress: jest.fn().mockReturnValue(null),
    };

    const mockAutoMatch = {
      running: false,
      runAutoMatchCycle: jest.fn(),
      processTransaction: jest.fn(),
    };

    const mockUnmatchedQueue = {
      listPending: jest.fn(),
      findById: jest.fn(),
      resolve: jest.fn(),
      dismiss: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [ReconciliationController],
      providers: [
        { provide: ReconciliationWorkerService, useValue: mockWorker },
        { provide: BackfillService, useValue: mockBackfill },
        { provide: AutoMatchService, useValue: mockAutoMatch },
        { provide: UnmatchedQueueRepository, useValue: mockUnmatchedQueue },
      ],
    })
      .overrideGuard(NetworkSafetyGuard)
      .useValue({ canActivate: () => true })
      .compile();

    controller = module.get<ReconciliationController>(ReconciliationController);
    worker = module.get(
      ReconciliationWorkerService,
    ) as jest.Mocked<ReconciliationWorkerService>;
    backfill = module.get(BackfillService) as jest.Mocked<BackfillService>;
    autoMatch = module.get(AutoMatchService) as jest.Mocked<AutoMatchService>;
    unmatchedQueue = module.get(
      UnmatchedQueueRepository,
    ) as jest.Mocked<UnmatchedQueueRepository>;
  });

  it("should be defined", () => {
    expect(controller).toBeDefined();
  });

  // ─── Status ────────────────────────────────────────────────────────────────

  describe("getStatus", () => {
    it("returns worker running state and last report", () => {
      worker.getLastReport.mockReturnValue({ id: "rpt-1" } as never);

      const result = controller.getStatus();

      expect(result.running).toBe(false);
      expect(result.lastReport).toEqual({ id: "rpt-1" });
    });
  });

  // ─── Trigger ───────────────────────────────────────────────────────────────

  describe("trigger", () => {
    it("returns the reconciliation report on success", async () => {
      const report = { id: "rpt-1", matches: 5 } as never;
      worker.triggerManually.mockResolvedValue(report);

      const result = await controller.trigger();

      expect(result).toBe(report);
    });

    it("throws ConflictException when worker is already running", async () => {
      worker.triggerManually.mockRejectedValue(
        new Error("Reconciliation is already running"),
      );

      await expect(controller.trigger()).rejects.toThrow(ConflictException);
    });

    it("rethrows non-conflict errors", async () => {
      worker.triggerManually.mockRejectedValue(new Error("Database down"));

      await expect(controller.trigger()).rejects.toThrow("Database down");
    });
  });

  // ─── Backfill ──────────────────────────────────────────────────────────────

  describe("startBackfill", () => {
    it("returns backfill result on success", async () => {
      const config = { fromLedger: 100, toLedger: 200 } as never;
      const result = { processed: 10, persisted: 10 } as never;
      backfill.startBackfill.mockResolvedValue(result);

      const response = await controller.startBackfill(config);

      expect(response).toBe(result);
    });

    it("throws ConflictException when backfill already running", async () => {
      backfill.startBackfill.mockRejectedValue(
        new Error("A backfill job is already running"),
      );

      await expect(
        controller.startBackfill({ fromLedger: 100 } as never),
      ).rejects.toThrow(ConflictException);
    });
  });

  describe("getBackfillStatus", () => {
    it("returns current backfill progress", () => {
      backfill.getBackfillProgress.mockReturnValue({
        fromLedger: 100,
        toLedger: 200,
        processed: 50,
      } as never);

      const result = controller.getBackfillStatus();

      expect(result).toEqual({ fromLedger: 100, toLedger: 200, processed: 50 });
    });

    it("returns null when no backfill in progress", () => {
      backfill.getBackfillProgress.mockReturnValue(null);
      expect(controller.getBackfillStatus()).toBeNull();
    });
  });

  // ─── Auto-match ────────────────────────────────────────────────────────────

  describe("getAutoMatchStatus", () => {
    it("returns auto-match running state", () => {
      Object.defineProperty(autoMatch, "running", {
        value: true,
        writable: true,
      });
      expect(controller.getAutoMatchStatus()).toEqual({ running: true });
    });
  });

  describe("triggerAutoMatch", () => {
    it("returns cycle summary on success", async () => {
      autoMatch.runAutoMatchCycle.mockResolvedValue({
        processed: 10,
        matched: 8,
        queued: 1,
        unmatched: 1,
      });

      const result = await controller.triggerAutoMatch();

      expect(result.processed).toBe(10);
      expect(result.matched).toBe(8);
    });

    it("throws ConflictException when auto-match already running", async () => {
      Object.defineProperty(autoMatch, "running", {
        value: true,
        writable: true,
      });

      await expect(controller.triggerAutoMatch()).rejects.toThrow(
        ConflictException,
      );
    });
  });

  describe("processTransaction", () => {
    it("delegates to auto-match service", async () => {
      const tx = { txHash: "abc", amount: "10" } as never;
      const matchResult = { score: 0.9, matched: true } as never;
      autoMatch.processTransaction.mockResolvedValue(matchResult);

      const result = await controller.processTransaction(tx);

      expect(result).toBe(matchResult);
      expect(autoMatch.processTransaction).toHaveBeenCalledWith(tx);
    });
  });

  // ─── Unmatched queue ───────────────────────────────────────────────────────

  describe("listUnmatched", () => {
    it("returns paginated unmatched transactions", async () => {
      const page = {
        items: [{ id: "u1", txHash: "tx1" }],
        total: 1,
        hasMore: false,
      };
      unmatchedQueue.listPending.mockResolvedValue(page as never);

      const result = await controller.listUnmatched("10", "0");

      expect(result).toEqual(page);
      expect(unmatchedQueue.listPending).toHaveBeenCalledWith(10, 0);
    });

    it("uses defaults when limit/offset not provided", async () => {
      unmatchedQueue.listPending.mockResolvedValue({
        items: [],
        total: 0,
        hasMore: false,
      });

      await controller.listUnmatched(undefined, undefined);

      expect(unmatchedQueue.listPending).toHaveBeenCalledWith(20, 0);
    });

    it("clamps limit to max 100", async () => {
      unmatchedQueue.listPending.mockResolvedValue({
        items: [],
        total: 0,
        hasMore: false,
      });

      await controller.listUnmatched("500", "0");

      expect(unmatchedQueue.listPending).toHaveBeenCalledWith(100, 0);
    });
  });

  describe("getUnmatched", () => {
    it("returns unmatched transaction when found", async () => {
      unmatchedQueue.findById.mockResolvedValue({
        id: "u1",
        txHash: "tx1",
      } as never);

      const result = await controller.getUnmatched("u1");

      expect(result).toEqual({ id: "u1", txHash: "tx1" });
    });

    it("throws NotFoundException when not found", async () => {
      unmatchedQueue.findById.mockResolvedValue(null);

      await expect(controller.getUnmatched("missing")).rejects.toThrow(
        NotFoundException,
      );
    });
  });

  describe("resolveUnmatched", () => {
    it("resolves and returns status", async () => {
      unmatchedQueue.findById.mockResolvedValue({ id: "u1" } as never);
      unmatchedQueue.resolve.mockResolvedValue(undefined);

      const result = await controller.resolveUnmatched("u1", {
        resolvedBy: "GABC",
        note: "test",
      });

      expect(result).toEqual({ id: "u1", status: "resolved" });
      expect(unmatchedQueue.resolve).toHaveBeenCalledWith("u1", "GABC", "test");
    });

    it("throws NotFoundException when record not found", async () => {
      unmatchedQueue.findById.mockResolvedValue(null);

      await expect(
        controller.resolveUnmatched("missing", { resolvedBy: "GABC" }),
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe("dismissUnmatched", () => {
    it("dismisses and returns status", async () => {
      unmatchedQueue.findById.mockResolvedValue({ id: "u1" } as never);
      unmatchedQueue.dismiss.mockResolvedValue(undefined);

      const result = await controller.dismissUnmatched("u1", {
        resolvedBy: "GABC",
      });

      expect(result).toEqual({ id: "u1", status: "dismissed" });
    });

    it("throws NotFoundException when record not found", async () => {
      unmatchedQueue.findById.mockResolvedValue(null);

      await expect(
        controller.dismissUnmatched("missing", { resolvedBy: "GABC" }),
      ).rejects.toThrow(NotFoundException);
    });
  });
});
