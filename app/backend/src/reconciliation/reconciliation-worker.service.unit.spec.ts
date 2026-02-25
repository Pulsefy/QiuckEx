import { Test, TestingModule } from '@nestjs/testing';

import { AppConfigService } from '../config/app-config.service';
import { ReconciliationWorkerService } from './reconciliation-worker.service';
import { ReconciliationService } from './reconciliation.service';
import { ReconciliationReport } from './types/reconciliation.types';

const makeEmptyReport = (): ReconciliationReport => ({
  runId: 'test-run-id',
  startedAt: new Date().toISOString(),
  completedAt: new Date().toISOString(),
  durationMs: 100,
  escrows: { processed: 0, updated: 0, noOp: 0, skipped: 0, irreconcilable: 0, results: [] },
  payments: { processed: 0, updated: 0, noOp: 0, skipped: 0, irreconcilable: 0, results: [] },
});

const mockReconciliationService = {
  runReconciliation: jest.fn(),
};

const mockConfig: Partial<AppConfigService> = {
  reconciliationBatchSize: 50,
};

describe('ReconciliationWorkerService', () => {
  let worker: ReconciliationWorkerService;

  beforeEach(async () => {
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ReconciliationWorkerService,
        { provide: ReconciliationService, useValue: mockReconciliationService },
        { provide: AppConfigService, useValue: mockConfig },
      ],
    }).compile();

    worker = module.get<ReconciliationWorkerService>(ReconciliationWorkerService);
  });

  it('runs a reconciliation and stores the last report', async () => {
    const report = makeEmptyReport();
    mockReconciliationService.runReconciliation.mockResolvedValue(report);

    await worker.triggerManually();

    expect(mockReconciliationService.runReconciliation).toHaveBeenCalledWith(50);
    expect(worker.getLastReport()).toBe(report);
    expect(worker.running).toBe(false);
  });

  it('throws ConflictException when a run is already in progress', async () => {
    // Simulate long-running job
    mockReconciliationService.runReconciliation.mockImplementation(
      () => new Promise((resolve) => setTimeout(() => resolve(makeEmptyReport()), 5000)),
    );

    // Start without awaiting
    const first = worker.triggerManually();

    await expect(worker.triggerManually()).rejects.toThrow('Reconciliation is already running');

    // Cleanup
    jest.useRealTimers();
    await first.catch(() => undefined);
  });

  it('resets isRunning flag after a failed run', async () => {
    mockReconciliationService.runReconciliation.mockRejectedValue(new Error('Horizon down'));

    await expect(worker.triggerManually()).rejects.toThrow('Horizon down');
    expect(worker.running).toBe(false);
  });

  it('returns null for lastReport before any run', () => {
    expect(worker.getLastReport()).toBeNull();
  });

  it('handleCron skips when already running', async () => {
    // Simulate in-progress state
    (worker as unknown as { isRunning: boolean }).isRunning = true;

    await worker.handleCron();

    expect(mockReconciliationService.runReconciliation).not.toHaveBeenCalled();
  });
});
