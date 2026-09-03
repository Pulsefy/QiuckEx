import { ReconciliationService } from './reconciliation.service';
import { ReconciliationRunRepository } from './reconciliation-run.repository';
import { AppConfigService } from '../config/app-config.service';
import { SupabaseService } from '../supabase/supabase.service';
import { MetricsService } from '../metrics/metrics.service';
import { SentryService } from '../sentry/sentry.service';
import { ReconciliationAction, ReconciliationReport } from './types/reconciliation.types';

describe('ReconciliationService (BE-124)', () => {
  let service: ReconciliationService;

  const config = {
    network: 'testnet',
    reconciliationBatchSize: 50,
    reconciliationDriftCountThreshold: 5,
    reconciliationDriftAmountThresholdStroops: '0',
    reconciliationConsecutiveFailureAlertThreshold: 3,
  };

  const supabase = {
    fetchPendingEscrows: jest.fn(),
    fetchPendingPayments: jest.fn(),
    fetchPaidPayments: jest.fn(),
  };

  const metrics = {
    recordExternalCall: jest.fn(),
    recordError: jest.fn(),
    setReconciliationDriftActive: jest.fn(),
    setReconciliationConsecutiveFailures: jest.fn(),
  };

  const sentry = {
    captureMessage: jest.fn(),
    captureException: jest.fn(),
  };

  const runRepository = {
    save: jest.fn().mockResolvedValue(undefined),
    countConsecutiveIncompleteRuns: jest.fn().mockResolvedValue(0),
    listRuns: jest.fn(),
    findById: jest.fn(),
  };

  beforeEach(() => {
    jest.clearAllMocks();

    supabase.fetchPendingEscrows.mockResolvedValue([]);
    supabase.fetchPendingPayments.mockResolvedValue([]);
    supabase.fetchPaidPayments.mockResolvedValue([]);

    service = new ReconciliationService(
      config as unknown as AppConfigService,
      supabase as unknown as SupabaseService,
      metrics as unknown as MetricsService,
      runRepository as unknown as ReconciliationRunRepository,
      sentry as unknown as SentryService,
    );
  });

  describe('clean run', () => {
    it('classifies as success, persists a summary, and raises no alert', async () => {
      const report: ReconciliationReport = await service.runReconciliation(10);

      expect(report.alert).toBeUndefined();
      expect(report.totalsComparison?.payments.exceedsThreshold).toBe(false);

      expect(runRepository.save).toHaveBeenCalledWith(
        expect.objectContaining({
          status: 'success',
          driftExceeded: false,
          escrowsProcessed: 0,
          paymentsProcessed: 0,
        }),
      );
      expect(sentry.captureMessage).not.toHaveBeenCalled();
      expect(metrics.setReconciliationDriftActive).toHaveBeenCalledWith(0);
    });
  });

  describe('drift over threshold', () => {
    it('classifies as drift, raises a critical alert, and persists drift detail', async () => {
      // Simulate an observed payment total that diverges from the DB.
      (service as unknown as {
        comparePaymentTotals: () => Promise<unknown>;
      }).comparePaymentTotals = jest.fn().mockResolvedValue({
        payments: {
          expectedCount: 100,
          observedCount: 80,
          countDiscrepancy: 20,
          expectedTotalAmount: '1000000',
          observedTotalAmount: '900000',
          amountDiscrepancy: '100000',
          exceedsThreshold: true,
        },
      });

      const report: ReconciliationReport = await service.runReconciliation(10);

      expect(report.alert).toBeDefined();
      expect(report.alert?.severity).toBe('critical');

      expect(metrics.recordError).toHaveBeenCalledWith(
        'reconciliation',
        'critical_drift',
      );
      expect(sentry.captureMessage).toHaveBeenCalledWith(
        expect.stringContaining('Critical payment discrepancy'),
        'fatal',
        expect.objectContaining({ runId: report.runId }),
      );

      expect(runRepository.save).toHaveBeenCalledWith(
        expect.objectContaining({
          status: 'drift',
          driftExceeded: true,
          countDiscrepancy: 20,
          amountDiscrepancy: '100000',
          alertSeverity: 'critical',
        }),
      );
      expect(metrics.setReconciliationDriftActive).toHaveBeenCalledWith(1);
    });

    it('under the threshold classifies as success with no alert', async () => {
      (service as unknown as {
        comparePaymentTotals: () => Promise<unknown>;
      }).comparePaymentTotals = jest.fn().mockResolvedValue({
        payments: {
          expectedCount: 10,
          observedCount: 7,
          countDiscrepancy: 3,
          expectedTotalAmount: '1000',
          observedTotalAmount: '1000',
          amountDiscrepancy: '0',
          exceedsThreshold: false,
        },
      });

      const report: ReconciliationReport = await service.runReconciliation(10);

      expect(report.alert).toBeUndefined();
      expect(runRepository.save).toHaveBeenCalledWith(
        expect.objectContaining({ status: 'success' }),
      );
      expect(sentry.captureMessage).not.toHaveBeenCalled();
    });
  });

  describe('run failure', () => {
    it('persists a failed summary and alerts when consecutive failures reach the threshold', async () => {
      // Three most recent runs are all failed/skipped.
      runRepository.countConsecutiveIncompleteRuns.mockResolvedValue(3);

      await service.recordFailedRun('Horizon unavailable');

      expect(runRepository.save).toHaveBeenCalledWith(
        expect.objectContaining({
          status: 'failed',
          failureReason: 'Horizon unavailable',
        }),
      );

      expect(metrics.recordError).toHaveBeenCalledWith(
        'reconciliation',
        'consecutive_failures',
      );
      expect(sentry.captureMessage).toHaveBeenCalledWith(
        expect.stringContaining('3 consecutive failed/skipped run(s)'),
        'warning',
        expect.objectContaining({ consecutiveFailures: 3, threshold: 3 }),
      );
    });

    it('does not alert when the streak is below the threshold', async () => {
      runRepository.countConsecutiveIncompleteRuns.mockResolvedValue(2);

      await service.recordFailedRun('temporary glitch');

      expect(metrics.recordError).not.toHaveBeenCalledWith(
        'reconciliation',
        'consecutive_failures',
      );
      expect(sentry.captureMessage).not.toHaveBeenCalled();
    });

    it('alerts only once per streak', async () => {
      runRepository.countConsecutiveIncompleteRuns.mockResolvedValue(3);

      await service.recordFailedRun('failure 1');
      await service.recordFailedRun('failure 2');

      expect(
        sentry.captureMessage.mock.calls.filter(([msg]) =>
          String(msg).includes('consecutive failed/skipped'),
        ),
      ).toHaveLength(1);
    });

    it('records skipped runs the same way', async () => {
      runRepository.countConsecutiveIncompleteRuns.mockResolvedValue(3);

      await service.recordSkippedRun('Previous run still in progress');

      expect(runRepository.save).toHaveBeenCalledWith(
        expect.objectContaining({
          status: 'skipped',
          skippedReason: 'Previous run still in progress',
        }),
      );
      expect(sentry.captureMessage).toHaveBeenCalledWith(
        expect.stringContaining('3 consecutive'),
        'warning',
        expect.anything(),
      );
    });

    it('resets the consecutive-failure alert once a run completes', async () => {
      runRepository.countConsecutiveIncompleteRuns
        .mockResolvedValueOnce(3) // failed streak
        .mockResolvedValueOnce(3) // second failure in same streak
        .mockResolvedValueOnce(0); // clean run after

      await service.recordFailedRun('failure 1');
      await service.recordFailedRun('failure 2');
      await service.runReconciliation(10);

      expect(runRepository.save).toHaveBeenLastCalledWith(
        expect.objectContaining({ status: 'success' }),
      );

      // A fresh streak re-triggers the alert.
      runRepository.countConsecutiveIncompleteRuns.mockResolvedValue(3);
      await service.recordFailedRun('failure 3');
      expect(sentry.captureMessage).toHaveBeenCalledWith(
        expect.stringContaining('consecutive failed/skipped'),
        'warning',
        expect.anything(),
      );
    });
  });

  describe('buildDriftDetails', () => {
    it('collapses non-actionable records to NoOp', () => {
      const report = {
        runId: 'r1',
        escrows: {
          results: [
            {
              id: 'e1',
              onChainState: 'non_existent',
              previousDbStatus: 'pending',
              resolvedDbStatus: null,
              action: ReconciliationAction.Flagged,
              irreconcilable: true,
              irreconcilableReason: 'account missing',
            },
            {
              id: 'e2',
              onChainState: 'active',
              previousDbStatus: 'active',
              resolvedDbStatus: 'active',
              action: ReconciliationAction.NoOp,
            },
          ],
        },
        payments: { results: [] },
      } as unknown as ReconciliationReport;

      const details = (service as unknown as {
        buildDriftDetails: (report: ReconciliationReport) => unknown[];
      }).buildDriftDetails(report);

      expect(details).toHaveLength(1);
      expect(details[0]).toEqual(
        expect.objectContaining({
          entityType: 'escrow',
          id: 'e1',
          action: ReconciliationAction.Flagged,
          irreconcilableReason: 'account missing',
        }),
      );
    });
  });
});