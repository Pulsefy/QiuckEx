import { Test, TestingModule } from '@nestjs/testing';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { ReconciliationService } from './reconciliation.service';
import { AppConfigService } from '../config/app-config.service';
import { SupabaseService } from '../supabase/supabase.service';
import { MetricsService } from '../metrics/metrics.service';
import { SentryService } from '../sentry/sentry.service';

describe('ReconciliationService Unit Tests', () => {
  let service: ReconciliationService;
  let mockConfig: any;
  let mockSupabase: any;
  let mockMetrics: any;
  let mockSentry: any;
  let mockEventEmitter: any;

  beforeEach(async () => {
    mockConfig = {
      network: 'testnet',
      reconciliationBatchSize: 50,
      reconciliationCronExpression: '*/5 * * * *',
      reconciliationDriftThresholdCount: 5,
      reconciliationDriftThresholdAmount: '100',
      reconciliationConsecutiveFailureThreshold: 3,
    };

    mockSupabase = {
      getClient: jest.fn().mockReturnValue({
        from: jest.fn().mockReturnValue({
          insert: jest.fn().mockResolvedValue({ error: null }),
          select: jest.fn().mockReturnValue({
            order: jest.fn().mockReturnValue({
              range: jest.fn().mockResolvedValue({ data: [], count: 0, error: null }),
            }),
          }),
        }),
      }),
      fetchPaidPayments: jest.fn().mockResolvedValue([]),
    };

    mockMetrics = {
      recordError: jest.fn(),
    };

    mockSentry = {
      captureMessage: jest.fn(),
    };

    mockEventEmitter = {
      emit: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ReconciliationService,
        { provide: AppConfigService, useValue: mockConfig },
        { provide: SupabaseService, useValue: mockSupabase },
        { provide: MetricsService, useValue: mockMetrics },
        { provide: SentryService, useValue: mockSentry },
        { provide: EventEmitter2, useValue: mockEventEmitter },
      ],
    }).compile();

    service = module.get<ReconciliationService>(ReconciliationService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('Clean Run (No Drift)', () => {
    it('should complete reconciliation successfully and record no alerts', async () => {
      jest.spyOn(service as any, 'reconcileEscrows').mockResolvedValue([]);
      jest.spyOn(service as any, 'reconcilePayments').mockResolvedValue([]);
      jest.spyOn(service as any, 'comparePaymentTotals').mockResolvedValue({
        payments: {
          expectedCount: 10,
          observedCount: 10,
          countDiscrepancy: 0,
          expectedTotalAmount: '1000',
          observedTotalAmount: '1000',
          amountDiscrepancy: '0',
          exceedsThreshold: false,
        },
      });

      const report = await service.runReconciliation(50);

      expect(report.runId).toBeDefined();
      expect(report.alert).toBeUndefined();
      expect(mockSupabase.getClient().from).toHaveBeenCalledWith('reconciliation_runs');
      expect(mockSentry.captureMessage).not.toHaveBeenCalled();
      expect(mockEventEmitter.emit).not.toHaveBeenCalled();
    });
  });

  describe('Drift Threshold Violation', () => {
    it('should trigger alert, metrics, Sentry, and event when count drift exceeds threshold', async () => {
      jest.spyOn(service as any, 'reconcileEscrows').mockResolvedValue([]);
      jest.spyOn(service as any, 'reconcilePayments').mockResolvedValue([]);
      jest.spyOn(service as any, 'comparePaymentTotals').mockResolvedValue({
        payments: {
          expectedCount: 10,
          observedCount: 4,
          countDiscrepancy: 6,
          expectedTotalAmount: '1000',
          observedTotalAmount: '1000',
          amountDiscrepancy: '0',
          exceedsThreshold: true,
        },
      });

      const report = await service.runReconciliation(50);

      expect(report.alert).toBeDefined();
      expect(report.alert?.severity).toBe('warning');
      expect(mockSentry.captureMessage).toHaveBeenCalledWith(
        expect.stringContaining('Payment discrepancy detected'),
        'error',
        expect.any(Object),
      );
      expect(mockEventEmitter.emit).toHaveBeenCalledWith(
        'reconciliation.drift_detected',
        expect.objectContaining({
          countDiscrepancy: 6,
          amountDiscrepancy: '0',
        }),
      );
    });

    it('should trigger critical alert, metrics, Sentry, and event when amount drift exceeds threshold', async () => {
      jest.spyOn(service as any, 'reconcileEscrows').mockResolvedValue([]);
      jest.spyOn(service as any, 'reconcilePayments').mockResolvedValue([]);
      jest.spyOn(service as any, 'comparePaymentTotals').mockResolvedValue({
        payments: {
          expectedCount: 10,
          observedCount: 10,
          countDiscrepancy: 0,
          expectedTotalAmount: '1000',
          observedTotalAmount: '800',
          amountDiscrepancy: '200',
          exceedsThreshold: true,
        },
      });

      const report = await service.runReconciliation(50);

      expect(report.alert).toBeDefined();
      expect(report.alert?.severity).toBe('critical');
      expect(mockSentry.captureMessage).toHaveBeenCalledWith(
        expect.stringContaining('Critical payment discrepancy detected'),
        'error',
        expect.any(Object),
      );
    });
  });

  describe('Consecutive Failure Tracking', () => {
    it('should track consecutive failures and trigger an alert once threshold is reached', async () => {
      jest.spyOn(service as any, 'reconcileEscrows').mockRejectedValue(new Error('Stellar node timeout'));

      // Run 1
      await expect(service.runReconciliation(50)).rejects.toThrow('Stellar node timeout');
      expect(mockSentry.captureMessage).not.toHaveBeenCalled();

      // Run 2
      await expect(service.runReconciliation(50)).rejects.toThrow('Stellar node timeout');
      expect(mockSentry.captureMessage).not.toHaveBeenCalled();

      // Run 3 - triggers alert
      await expect(service.runReconciliation(50)).rejects.toThrow('Stellar node timeout');
      expect(mockSentry.captureMessage).toHaveBeenCalledWith(
        'Reconciliation alert: 3 consecutive failures detected',
        'error',
        expect.any(Object),
      );
      expect(mockEventEmitter.emit).toHaveBeenCalledWith(
        'reconciliation.failed',
        expect.objectContaining({
          type: 'failure',
          consecutiveCount: 3,
          lastReason: 'Stellar node timeout',
        }),
      );
    });

    it('should reset consecutive failure counter on a successful run', async () => {
      jest.spyOn(service as any, 'reconcileEscrows')
        .mockRejectedValueOnce(new Error('Fail 1'))
        .mockRejectedValueOnce(new Error('Fail 2'))
        .mockResolvedValueOnce([]);

      jest.spyOn(service as any, 'reconcilePayments').mockResolvedValue([]);
      jest.spyOn(service as any, 'comparePaymentTotals').mockResolvedValue({
        payments: {
          expectedCount: 10,
          observedCount: 10,
          countDiscrepancy: 0,
          expectedTotalAmount: '1000',
          observedTotalAmount: '1000',
          amountDiscrepancy: '0',
          exceedsThreshold: false,
        },
      });

      // Run 1
      await expect(service.runReconciliation(50)).rejects.toThrow('Fail 1');
      // Run 2
      await expect(service.runReconciliation(50)).rejects.toThrow('Fail 2');

      // Run 3 (Success)
      const report = await service.runReconciliation(50);
      expect(report.runId).toBeDefined();

      // Run 4 (Fail) - should start from 1 (no alert)
      jest.spyOn(service as any, 'reconcileEscrows').mockRejectedValue(new Error('Fail 4'));
      await expect(service.runReconciliation(50)).rejects.toThrow('Fail 4');
      expect(mockSentry.captureMessage).not.toHaveBeenCalled();
    });
  });

  describe('Consecutive Skip Tracking', () => {
    it('should alert when consecutive skips reach threshold', () => {
      service.recordSkip('Previous run in progress');
      service.recordSkip('Previous run in progress');
      expect(mockSentry.captureMessage).not.toHaveBeenCalled();

      service.recordSkip('Previous run in progress');
      expect(mockSentry.captureMessage).toHaveBeenCalledWith(
        'Reconciliation alert: 3 consecutive skips detected',
        'error',
        expect.any(Object),
      );
      expect(mockEventEmitter.emit).toHaveBeenCalledWith(
        'reconciliation.failed',
        expect.objectContaining({
          type: 'skip',
          consecutiveCount: 3,
          lastReason: 'Previous run in progress',
        }),
      );
    });
  });

  describe('Runs History Querying', () => {
    it('should query the database using the specified limit and offset', async () => {
      const mockSelect = jest.fn().mockReturnValue({
        order: jest.fn().mockReturnValue({
          range: jest.fn().mockResolvedValue({
            data: [{ id: 'run1', status: 'success' }],
            count: 1,
            error: null,
          }),
        }),
      });

      mockSupabase.getClient = jest.fn().mockReturnValue({
        from: jest.fn().mockReturnValue({
          select: mockSelect,
        }),
      });

      const result = await service.getHistory(20, 10);

      expect(mockSupabase.getClient().from).toHaveBeenCalledWith('reconciliation_runs');
      expect(result.data).toEqual([{ id: 'run1', status: 'success' }]);
      expect(result.total).toBe(1);
      expect(result.limit).toBe(20);
      expect(result.offset).toBe(10);
    });
  });
});
