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

  describe("getStatus", () => {
    it("returns worker status", () => {
      const report = { runId: "r1" } as never;
      worker.getLastReport.mockReturnValue(report);

      const result = controller.getStatus();

      expect(result).toEqual({ running: false, lastReport: report });
    });
  });

  describe("trigger", () => {
    it("calls worker.triggerManually and returns the report", async () => {
      const report = { runId: "r1" } as never;
      worker.triggerManually.mockResolvedValue(report);

      const result = await controller.trigger();

      expect(result).toBe(report);
    });

    it("throws ConflictException when already running", async () => {
      worker.triggerManually.mockRejectedValue(
        new Error("Reconciliation is already running"),
      );

      await expect(controller.trigger()).rejects.toThrow(ConflictException);
    });

    it("re-throws non-conflict errors", async () => {
      worker.triggerManually.mockRejectedValue(new Error("boom"));

      await expect(controller.trigger()).rejects.toThrow("boom");
    });
  });

  describe("startBackfill", () => {
    it("calls backfill.startBackfill and returns the result", async () => {
      const config = { fromLedger: 1, toLedger: 100 } as never;
      const result_ = { fromLedger: 1, toLedger: 100 } as never;
      backfill.startBackfill.mockResolvedValue(result_);

      const result = await controller.startBackfill(config);

      expect(result).toBe(result_);
    });

    it("throws ConflictException when a backfill is already running", async () => {
      backfill.startBackfill.mockRejectedValue(
        new Error("A backfill job is already running"),
      );

      await expect(controller.startBackfill({} as never)).rejects.toThrow(
        ConflictException,
      );
    });

    it("re-throws non-conflict errors", async () => {
      backfill.startBackfill.mockRejectedValue(new Error("boom"));

      await expect(controller.startBackfill({} as never)).rejects.toThrow(
        "boom",
      );
    });
  });

  describe("getBackfillStatus", () => {
    it("returns null when no job", () => {
      backfill.getBackfillProgress.mockReturnValue(null);
      expect(controller.getBackfillStatus()).toBeNull();
    });

    it("returns progress when a job exists", () => {
      const progress = { fromLedger: 1, toLedger: 100 } as never;
      backfill.getBackfillProgress.mockReturnValue(progress);
      expect(controller.getBackfillStatus()).toBe(progress);
    });
  });

  describe("getAutoMatchStatus", () => {
    it("returns running flag", () => {
      expect(controller.getAutoMatchStatus()).toEqual({ running: false });
    });
  });

  describe("triggerAutoMatch", () => {
    it("throws ConflictException when already running", async () => {
      Object.defineProperty(autoMatch, "running", {
        value: true,
        writable: true,
      });

      await expect(controller.triggerAutoMatch()).rejects.toThrow(
        ConflictException,
      );
    });

    it("runs cycle when not running and returns counters", async () => {
      const counters = {
        processed: 5,
        matched: 3,
        queued: 1,
        unmatched: 1,
      };
      autoMatch.runAutoMatchCycle.mockResolvedValue(counters);

      const result = await controller.triggerAutoMatch();

      expect(result).toEqual(counters);
      expect(autoMatch.runAutoMatchCycle).toHaveBeenCalled();
    });
  });

  describe("processTransaction", () => {
    it("delegates to autoMatch.processTransaction", async () => {
      const tx = { txHash: "0xabc" } as never;
      const matchResult = { score: 0.9 } as never;
      autoMatch.processTransaction.mockResolvedValue(matchResult);

      const result = await controller.processTransaction(tx);

      expect(result).toBe(matchResult);
      expect(autoMatch.processTransaction).toHaveBeenCalledWith(tx);
    });
  });

  describe("listUnmatched", () => {
    it("returns paginated unmatched items", async () => {
      const page = {
        items: [{ id: "u1" }],
        total: 1,
        hasMore: false,
      } as never;
      unmatchedQueue.listPending.mockResolvedValue(page);

      const result = await controller.listUnmatched("10", "0");

      expect(result).toEqual(page);
      expect(unmatchedQueue.listPending).toHaveBeenCalledWith(10, 0);
    });

    it("defaults limit to 20 and offset to 0", async () => {
      unmatchedQueue.listPending.mockResolvedValue({
        items: [],
        total: 0,
        hasMore: false,
      } as never);

      await controller.listUnmatched();

      expect(unmatchedQueue.listPending).toHaveBeenCalledWith(20, 0);
    });

    it("clamps limit to max 100", async () => {
      unmatchedQueue.listPending.mockResolvedValue({
        items: [],
        total: 0,
        hasMore: false,
      } as never);

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
