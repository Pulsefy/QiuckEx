
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

import { Test, TestingModule } from '@nestjs/testing';
import { ReconciliationController } from './reconciliation.controller';
import { ReconciliationWorkerService } from './reconciliation-worker.service';
import { BackfillService } from './backfill.service';
import { AppConfigService } from '../config/app-config.service';
import { ConflictException } from '@nestjs/common';
import { Response } from 'express';
import { ReconciliationReport, ReconciliationAction, EscrowDbStatus, OnChainState } from './types/reconciliation.types';

describe('ReconciliationController', () => {
  let controller: ReconciliationController;
  let workerService: jest.Mocked<ReconciliationWorkerService>;
  let configService: jest.Mocked<AppConfigService>;

  beforeEach(async () => {
    workerService = {
      getLastReport: jest.fn(),
      triggerManually: jest.fn(),
      running: false,
    } as unknown as jest.Mocked<ReconciliationWorkerService>;

    const backfillService = {
      startBackfill: jest.fn(),
      getBackfillProgress: jest.fn(),
    } as unknown as jest.Mocked<BackfillService>;

    configService = {
      network: 'testnet',
    } as unknown as jest.Mocked<AppConfigService>;


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

        { provide: ReconciliationWorkerService, useValue: workerService },
        { provide: BackfillService, useValue: backfillService },
        { provide: AppConfigService, useValue: configService },
      ],
    }).compile();

    controller = module.get<ReconciliationController>(ReconciliationController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('exportReport', () => {
    const mockReport: ReconciliationReport = {
      runId: '123-abc',
      startedAt: '2024-01-01T00:00:00Z',
      completedAt: '2024-01-01T00:00:01Z',
      durationMs: 1000,
      escrows: {
        processed: 10,
        updated: 0,
        noOp: 10,
        skipped: 0,
        irreconcilable: 1,
        results: [
          {
            id: 'esc-1',
            contractAddress: 'GABC',
            previousDbStatus: EscrowDbStatus.Pending,
            onChainState: OnChainState.Unknown,
            resolvedDbStatus: null,
            action: ReconciliationAction.Flagged,
            irreconcilable: true,
            irreconcilableReason: 'Not found on chain',
          },
        ],
      },
      payments: {
        processed: 20,
        updated: 0,
        noOp: 20,
        skipped: 0,
        irreconcilable: 0,
        results: [],
      },
    };

    it('should throw ConflictException if no report exists', () => {
      workerService.getLastReport.mockReturnValue(null);
      const res = { setHeader: jest.fn(), send: jest.fn(), json: jest.fn() } as unknown as jest.Mocked<Response>;

      expect(() => controller.exportReport('json', res)).toThrow(ConflictException);
    });

    it('should export in JSON format by default', () => {
      workerService.getLastReport.mockReturnValue(mockReport);
      const res = { setHeader: jest.fn(), json: jest.fn(), send: jest.fn() } as unknown as jest.Mocked<Response>;

      controller.exportReport('json', res);

      expect(res.setHeader).toHaveBeenCalledWith('Content-Type', 'application/json');
      expect(res.setHeader).toHaveBeenCalledWith('Content-Disposition', 'attachment; filename="rc-report-123-abc.json"');
      
      expect(res.json).toHaveBeenCalled();
      const exportData = res.json.mock.calls[0][0];
      
      expect(exportData.runId).toEqual('123-abc');
      expect(exportData.environment.network).toEqual('testnet');
      expect(exportData.blockers).toHaveLength(1);
      expect(exportData.blockers[0]).toContain('Escrow esc-1');
      expect(exportData.timestamps.startedAt).toEqual('2024-01-01T00:00:00Z');
    });

    it('should export in markdown format', () => {
      workerService.getLastReport.mockReturnValue(mockReport);
      const res = { setHeader: jest.fn(), send: jest.fn(), json: jest.fn() } as unknown as jest.Mocked<Response>;

      controller.exportReport('markdown', res);

      expect(res.setHeader).toHaveBeenCalledWith('Content-Type', 'text/markdown');
      expect(res.setHeader).toHaveBeenCalledWith('Content-Disposition', 'attachment; filename="rc-report-123-abc.md"');
      
      expect(res.send).toHaveBeenCalled();
      const markdown = res.send.mock.calls[0][0];
      
      expect(markdown).toContain('# Release Candidate Validation Report');
      expect(markdown).toContain('**Run ID**: `123-abc`');
      expect(markdown).toContain('**Network**: `testnet`');
      expect(markdown).toContain('- Escrow esc-1: Not found on chain');
      expect(markdown).toContain('✅ No discrepancy alerts.');

    });
  });
});
