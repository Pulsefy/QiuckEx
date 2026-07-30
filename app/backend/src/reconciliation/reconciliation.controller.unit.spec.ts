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
