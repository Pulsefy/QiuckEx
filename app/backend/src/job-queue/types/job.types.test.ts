/**
 * Basic type checking tests for job queue types
 * These tests verify that the types are correctly defined and can be used
 */

import {
  JobType,
  JobStatus,
  Job,
  RetryPolicy,
  CancellationToken,
  JobHandler,
  WebhookDeliveryPayload,
  RecurringPaymentPayload,
  ExportGenerationPayload,
  ReconciliationPayload,
  StellarReconnectPayload,
} from '../index';

describe('Job Queue Types', () => {
  describe('JobType enum', () => {
    it('should have all 5 job types defined', () => {
      expect(JobType.WEBHOOK_DELIVERY).toBe('webhook_delivery');
      expect(JobType.RECURRING_PAYMENT).toBe('recurring_payment');
      expect(JobType.EXPORT_GENERATION).toBe('export_generation');
      expect(JobType.RECONCILIATION).toBe('reconciliation');
      expect(JobType.STELLAR_RECONNECT).toBe('stellar_reconnect');
    });
  });

  describe('JobStatus enum', () => {
    it('should have all 5 job statuses defined', () => {
      expect(JobStatus.PENDING).toBe('pending');
      expect(JobStatus.RUNNING).toBe('running');
      expect(JobStatus.COMPLETED).toBe('completed');
      expect(JobStatus.FAILED).toBe('failed');
      expect(JobStatus.CANCELLED).toBe('cancelled');
    });
  });

  describe('Job interface', () => {
    it('should allow creating a valid job object', () => {
      const job: Job<WebhookDeliveryPayload> = {
        id: '123e4567-e89b-12d3-a456-426614174000',
        type: JobType.WEBHOOK_DELIVERY,
        payload: {
          recipientPublicKey: 'GABC123',
          webhookUrl: 'https://example.com/webhook',
          eventType: 'payment.received',
          eventId: 'evt_123',
          payload: { amount: '100' },
        },
        status: JobStatus.PENDING,
        attempts: 0,
        maxAttempts: 5,
        createdAt: new Date(),
        scheduledAt: new Date(),
        startedAt: null,
        completedAt: null,
        failureReason: null,
        visibilityTimeout: null,
      };

      expect(job.type).toBe(JobType.WEBHOOK_DELIVERY);
      expect(job.status).toBe(JobStatus.PENDING);
      expect(job.payload.webhookUrl).toBe('https://example.com/webhook');
    });
  });

  describe('RetryPolicy interface', () => {
    it('should allow creating a valid retry policy', () => {
      const policy: RetryPolicy = {
        maxAttempts: 5,
        backoffStrategy: 'exponential',
        initialDelayMs: 60000,
        maxDelayMs: 7200000,
        visibilityTimeoutMs: 300000,
      };

      expect(policy.maxAttempts).toBe(5);
      expect(policy.backoffStrategy).toBe('exponential');
    });

    it('should support all backoff strategies', () => {
      const fixed: RetryPolicy['backoffStrategy'] = 'fixed';
      const linear: RetryPolicy['backoffStrategy'] = 'linear';
      const exponential: RetryPolicy['backoffStrategy'] = 'exponential';

      expect(fixed).toBe('fixed');
      expect(linear).toBe('linear');
      expect(exponential).toBe('exponential');
    });
  });

  describe('Job Payload interfaces', () => {
    it('should allow creating WebhookDeliveryPayload', () => {
      const payload: WebhookDeliveryPayload = {
        recipientPublicKey: 'GABC123',
        webhookUrl: 'https://example.com/webhook',
        eventType: 'payment.received',
        eventId: 'evt_123',
        payload: { amount: '100' },
      };

      expect(payload.eventType).toBe('payment.received');
    });

    it('should allow creating RecurringPaymentPayload', () => {
      const payload: RecurringPaymentPayload = {
        recurringLinkId: 'link_123',
        executionId: 'exec_456',
        recipientAddress: 'GDEF456',
        amount: '50.00',
        asset: 'USDC',
        assetIssuer: 'GISSUER',
        memo: 'Monthly payment',
        memoType: 'text',
      };

      expect(payload.asset).toBe('USDC');
    });

    it('should allow creating ExportGenerationPayload', () => {
      const payload: ExportGenerationPayload = {
        userId: 'user_123',
        exportType: 'transactions',
        filters: { startDate: '2024-01-01' },
        format: 'csv',
        deliveryMethod: 'download',
      };

      expect(payload.exportType).toBe('transactions');
    });

    it('should allow creating ReconciliationPayload', () => {
      const payload: ReconciliationPayload = {
        batchSize: 100,
        startLedger: 1000,
        endLedger: 2000,
      };

      expect(payload.batchSize).toBe(100);
    });

    it('should allow creating StellarReconnectPayload', () => {
      const payload: StellarReconnectPayload = {
        contractId: 'contract_123',
        lastCursor: 'cursor_abc',
      };

      expect(payload.contractId).toBe('contract_123');
    });
  });

  describe('CancellationToken interface', () => {
    it('should define required methods', () => {
      const token: CancellationToken = {
        isCancelled: () => false,
        throwIfCancelled: () => {},
      };

      expect(token.isCancelled()).toBe(false);
      expect(() => token.throwIfCancelled()).not.toThrow();
    });
  });

  describe('JobHandler interface', () => {
    it('should define required methods', () => {
      const handler: JobHandler<WebhookDeliveryPayload> = {
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        execute: async (_job, _token) => {},
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        validate: async (_payload) => {},
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        onFailure: async (_job, _error) => {},
      };

      expect(handler.execute).toBeDefined();
      expect(handler.validate).toBeDefined();
      expect(handler.onFailure).toBeDefined();
    });
  });
});
