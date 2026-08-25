/**
 * SEP-24 Polling Service – Unit Tests
 *
 * Covers:
 *   - Status progression (initiated → pending → completed)
 *   - Terminal failure path (anchor returns 'error')
 *   - Stuck detection and flagging
 *   - On-chain reconciliation trigger on completion
 *   - Graceful handling of anchor poll failures
 */

import { Test, TestingModule } from '@nestjs/testing';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { sep24Config } from '../config/sep24.config';
import { Sep24PollingService } from './sep24-polling.service';
import { Sep24TransactionRepository } from './sep24-transaction.repository';
import { AnchorClientService } from './anchor-client.service';
import { AppConfigService } from '../config/app-config.service';
import { MetricsService } from '../metrics/metrics.service';
import {
  Sep24AnchorStatus,
  Sep24InternalStatus,
  Sep24TransactionRecord,
} from './types/sep24.types';
import { NotificationEvent } from '../events/notification.events';

// ─── Mocks ──────────────────────────────────────────────────────────────────

const mockRepository = {
  findInFlight: jest.fn(),
  findStuck: jest.fn(),
  updateStatus: jest.fn(),
  incrementPollFailures: jest.fn(),
  flagAsStuck: jest.fn(),
  markReconciled: jest.fn(),
  findById: jest.fn(),
};

const mockAnchorClient = {
  pollTransaction: jest.fn(),
};

const mockAppConfig = {
  network: 'testnet',
};

const mockMetrics = {
  recordExternalCall: jest.fn(),
  recordError: jest.fn(),
};

const mockEventEmitter = {
  emit: jest.fn(),
};

const mockHorizonServer = {
  transactions: jest.fn().mockReturnThis(),
  transaction: jest.fn().mockReturnThis(),
  call: jest.fn(),
};

const mockReconciliationService = {
  runReconciliation: jest.fn(),
};

// ─── Helpers ─────────────────────────────────────────────────────────────────

function makeRecord(
  overrides: Partial<Sep24TransactionRecord> = {},
): Sep24TransactionRecord {
  return {
    id: 'rec-1',
    anchor_transaction_id: 'anchor-tx-1',
    anchor_domain: 'test.anchor.org',
    type: 'deposit',
    status: Sep24InternalStatus.Initiated,
    anchor_status: null,
    stellar_tx_hash: null,
    amount: '100.00',
    asset_code: 'USDC',
    asset_issuer: null,
    user_account: 'GABC123',
    interactive_url: 'https://test.anchor.org/sep24/interactive',
    created_at: new Date(Date.now() - 5_000).toISOString(),
    updated_at: new Date(Date.now() - 5_000).toISOString(),
    last_polled_at: null,
    poll_failure_count: 0,
    failure_reason: null,
    terminal_at: null,
    ...overrides,
  };
}

function anchorResponse(status: string, extra: Record<string, unknown> = {}) {
  return {
    success: true,
    httpStatus: 200,
    error: null,
    data: {
      transaction: {
        id: 'anchor-tx-1',
        kind: 'deposit',
        status,
        stellar_transaction_id: null,
        ...extra,
      },
    },
  };
}

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('Sep24PollingService', () => {
  let service: Sep24PollingService;

  beforeEach(async () => {
    jest.clearAllMocks();

    // Default: no in-flight, no stuck
    mockRepository.findInFlight.mockResolvedValue([]);
    mockRepository.findStuck.mockResolvedValue([]);
    mockRepository.updateStatus.mockResolvedValue(undefined);
    mockRepository.incrementPollFailures.mockResolvedValue(undefined);
    mockRepository.flagAsStuck.mockResolvedValue(undefined);
    mockRepository.markReconciled.mockResolvedValue(undefined);

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        Sep24PollingService,
        { provide: Sep24TransactionRepository, useValue: mockRepository },
        { provide: AnchorClientService, useValue: mockAnchorClient },
        { provide: AppConfigService, useValue: mockAppConfig },
        { provide: MetricsService, useValue: mockMetrics },
        { provide: EventEmitter2, useValue: mockEventEmitter },
        {
          provide: sep24Config.KEY,
          useValue: {
            stuckThresholdMs: 3_600_000,
            maxPollFailures: 5,
            batchSize: 50,
          },
        },
        // ReconciliationService is optional — omit to test without it
      ],
    }).compile();

    service = module.get<Sep24PollingService>(Sep24PollingService);

    // Replace internal Horizon.Server with a mock
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (service as any).horizonServer = mockHorizonServer;
    mockHorizonServer.transactions.mockReturnValue(mockHorizonServer);
    mockHorizonServer.transaction.mockReturnValue(mockHorizonServer);
  });

  // ── runPollCycle — empty queue ──────────────────────────────────────────────

  describe('runPollCycle', () => {
    it('returns zero counters when there are no in-flight transactions', async () => {
      const result = await service.runPollCycle();

      expect(result).toEqual({ processed: 0, updated: 0, terminal: 0, stuck: 0, failed: 0 });
      expect(mockAnchorClient.pollTransaction).not.toHaveBeenCalled();
    });
  });

  // ── Status progression ────────────────────────────────────────────────────

  describe('status progression', () => {
    it('transitions initiated → pending when anchor returns in-flight status', async () => {
      const record = makeRecord({ status: Sep24InternalStatus.Initiated });

      mockAnchorClient.pollTransaction.mockResolvedValue(
        anchorResponse(Sep24AnchorStatus.PendingAnchor),
      );

      const result = await service.pollOne(record);

      expect(result.previousInternalStatus).toBe(Sep24InternalStatus.Initiated);
      expect(result.newInternalStatus).toBe(Sep24InternalStatus.Pending);
      expect(result.terminal).toBe(false);
      expect(result.errorMessage).toBeNull();

      expect(mockRepository.updateStatus).toHaveBeenCalledWith(
        'rec-1',
        Sep24InternalStatus.Pending,
        Sep24AnchorStatus.PendingAnchor,
        null,
        { failureReason: undefined, terminalAt: undefined },
      );
    });

    it('stays in pending when anchor returns another in-flight status and status already pending', async () => {
      const record = makeRecord({ status: Sep24InternalStatus.Pending, anchor_status: Sep24AnchorStatus.PendingAnchor });

      mockAnchorClient.pollTransaction.mockResolvedValue(
        anchorResponse(Sep24AnchorStatus.PendingExternal),
      );

      const result = await service.pollOne(record);

      // Status changes from pending→pending (same), but anchor_status changed
      expect(result.newInternalStatus).toBe(Sep24InternalStatus.Pending);
      expect(result.terminal).toBe(false);
    });

    it('transitions pending → completed when anchor status is completed', async () => {
      const stellarTxHash = 'abc123stellar';
      const record = makeRecord({ status: Sep24InternalStatus.Pending });

      mockAnchorClient.pollTransaction.mockResolvedValue(
        anchorResponse(Sep24AnchorStatus.Completed, {
          stellar_transaction_id: stellarTxHash,
        }),
      );

      // Horizon mock returns a successful transaction
      mockHorizonServer.call.mockResolvedValue({ successful: true });

      const result = await service.pollOne(record);

      expect(result.newInternalStatus).toBe(Sep24InternalStatus.Completed);
      expect(result.stellarTxHash).toBe(stellarTxHash);
      expect(result.terminal).toBe(true);

      expect(mockRepository.updateStatus).toHaveBeenCalledWith(
        'rec-1',
        Sep24InternalStatus.Completed,
        Sep24AnchorStatus.Completed,
        stellarTxHash,
        expect.objectContaining({ terminalAt: expect.any(String) }),
      );
    });

    it('emits Sep24TransactionTerminal event on terminal transition', async () => {
      const record = makeRecord({ status: Sep24InternalStatus.Pending });

      mockAnchorClient.pollTransaction.mockResolvedValue(
        anchorResponse(Sep24AnchorStatus.Completed, {
          stellar_transaction_id: 'txhash',
        }),
      );

      mockHorizonServer.call.mockResolvedValue({ successful: true });

      await service.pollOne(record);

      expect(mockEventEmitter.emit).toHaveBeenCalledWith(
        NotificationEvent.Sep24TransactionTerminal,
        expect.objectContaining({
          transactionId: 'rec-1',
          anchorTransactionId: 'anchor-tx-1',
          internalStatus: Sep24InternalStatus.Completed,
        }),
      );
    });
  });

  // ── Terminal failure ──────────────────────────────────────────────────────

  describe('terminal failure', () => {
    it('transitions to failed when anchor returns error status', async () => {
      const record = makeRecord({ status: Sep24InternalStatus.Pending });

      mockAnchorClient.pollTransaction.mockResolvedValue(
        anchorResponse(Sep24AnchorStatus.Error, { message: 'KYC failed' }),
      );

      const result = await service.pollOne(record);

      expect(result.newInternalStatus).toBe(Sep24InternalStatus.Failed);
      expect(result.terminal).toBe(true);
      expect(result.errorMessage).toBeNull(); // poll itself succeeded

      expect(mockRepository.updateStatus).toHaveBeenCalledWith(
        'rec-1',
        Sep24InternalStatus.Failed,
        Sep24AnchorStatus.Error,
        null,
        expect.objectContaining({
          failureReason: 'KYC failed',
          terminalAt: expect.any(String),
        }),
      );
    });

    it('emits terminal event with error internalStatus on anchor_error', async () => {
      const record = makeRecord({ status: Sep24InternalStatus.Pending });

      mockAnchorClient.pollTransaction.mockResolvedValue(
        anchorResponse(Sep24AnchorStatus.AnchorError, { message: 'Anchor internal error' }),
      );

      await service.pollOne(record);

      expect(mockEventEmitter.emit).toHaveBeenCalledWith(
        NotificationEvent.Sep24TransactionTerminal,
        expect.objectContaining({ internalStatus: Sep24InternalStatus.Failed }),
      );
    });

    it('transitions to refunded when anchor returns refunded status', async () => {
      const record = makeRecord({ status: Sep24InternalStatus.Pending });

      mockAnchorClient.pollTransaction.mockResolvedValue(
        anchorResponse(Sep24AnchorStatus.Refunded),
      );

      const result = await service.pollOne(record);

      expect(result.newInternalStatus).toBe(Sep24InternalStatus.Refunded);
      expect(result.terminal).toBe(true);
    });
  });

  // ── Anchor poll failure handling ──────────────────────────────────────────

  describe('anchor poll failure', () => {
    it('increments failure counter and returns error when anchor is unreachable', async () => {
      const record = makeRecord();

      mockAnchorClient.pollTransaction.mockResolvedValue({
        success: false,
        data: null,
        httpStatus: null,
        error: 'Connection refused',
      });

      const result = await service.pollOne(record);

      expect(result.errorMessage).toBe('Connection refused');
      expect(result.newInternalStatus).toBe(Sep24InternalStatus.Initiated); // unchanged
      expect(mockRepository.incrementPollFailures).toHaveBeenCalledWith('rec-1', 'Connection refused');
      expect(mockRepository.updateStatus).not.toHaveBeenCalled();
    });

    it('increments failure counter on HTTP error from anchor', async () => {
      const record = makeRecord();

      mockAnchorClient.pollTransaction.mockResolvedValue({
        success: false,
        data: null,
        httpStatus: 503,
        error: 'Anchor returned HTTP 503',
      });

      const result = await service.pollOne(record);

      expect(result.errorMessage).not.toBeNull();
      expect(mockRepository.incrementPollFailures).toHaveBeenCalledTimes(1);
    });
  });

  // ── Stuck detection ──────────────────────────────────────────────────────

  describe('stuck detection', () => {
    it('flags stuck transactions and emits Sep24TransactionStuck event', async () => {
      const stuckRecord = makeRecord({
        id: 'stuck-1',
        anchor_transaction_id: 'anchor-stuck-1',
        status: Sep24InternalStatus.Pending,
        created_at: new Date(Date.now() - 2 * 3_600_000).toISOString(), // 2 hours ago
      });

      mockRepository.findStuck.mockResolvedValue([stuckRecord]);
      mockRepository.findInFlight.mockResolvedValue([]);

      const summary = await service.runPollCycle();

      expect(summary.stuck).toBe(1);
      expect(mockRepository.flagAsStuck).toHaveBeenCalledWith(
        'stuck-1',
        expect.stringContaining('in-flight for more than'),
      );
      expect(mockEventEmitter.emit).toHaveBeenCalledWith(
        NotificationEvent.Sep24TransactionStuck,
        expect.objectContaining({
          transactionId: 'stuck-1',
          anchorTransactionId: 'anchor-stuck-1',
        }),
      );
    });

    it('does not flag recently-initiated transactions as stuck', async () => {
      // findStuck returns nothing (all recent enough)
      mockRepository.findStuck.mockResolvedValue([]);

      const record = makeRecord({
        status: Sep24InternalStatus.Initiated,
        created_at: new Date(Date.now() - 30_000).toISOString(), // 30 seconds ago
      });

      mockRepository.findInFlight.mockResolvedValue([record]);
      mockAnchorClient.pollTransaction.mockResolvedValue(
        anchorResponse(Sep24AnchorStatus.PendingUserTransferStart),
      );

      const summary = await service.runPollCycle();

      expect(summary.stuck).toBe(0);
      expect(mockRepository.flagAsStuck).not.toHaveBeenCalled();
    });

    it('counts stuck transactions separately from processed', async () => {
      const stuckRecord = makeRecord({ id: 'stuck-2', status: Sep24InternalStatus.Pending });
      const inflightRecord = makeRecord({ id: 'inflight-1' });

      mockRepository.findStuck.mockResolvedValue([stuckRecord]);
      mockRepository.findInFlight.mockResolvedValue([inflightRecord]);
      mockAnchorClient.pollTransaction.mockResolvedValue(
        anchorResponse(Sep24AnchorStatus.PendingAnchor),
      );

      const summary = await service.runPollCycle();

      expect(summary.stuck).toBe(1);
      expect(summary.processed).toBe(1);
      expect(summary.updated).toBe(1);
    });
  });

  // ── On-chain reconciliation ──────────────────────────────────────────────

  describe('on-chain reconciliation', () => {
    it('marks transaction reconciled when Horizon confirms the tx', async () => {
      const record = makeRecord({ status: Sep24InternalStatus.Pending });
      const stellarTxHash = 'confirmed-stellar-hash';

      mockAnchorClient.pollTransaction.mockResolvedValue(
        anchorResponse(Sep24AnchorStatus.Completed, {
          stellar_transaction_id: stellarTxHash,
        }),
      );

      // Horizon confirms the transaction
      mockHorizonServer.call.mockResolvedValue({ successful: true });

      const result = await service.pollOne(record);

      expect(result.reconciled).toBe(true);
      expect(mockRepository.markReconciled).toHaveBeenCalledWith('rec-1');
      expect(mockEventEmitter.emit).toHaveBeenCalledWith(
        NotificationEvent.Sep24TransactionReconciled,
        expect.objectContaining({
          transactionId: 'rec-1',
          stellarTxHash,
          type: 'deposit',
        }),
      );
    });

    it('does not mark reconciled when Horizon says transaction was unsuccessful', async () => {
      const record = makeRecord({ status: Sep24InternalStatus.Pending });

      mockAnchorClient.pollTransaction.mockResolvedValue(
        anchorResponse(Sep24AnchorStatus.Completed, {
          stellar_transaction_id: 'failed-hash',
        }),
      );

      mockHorizonServer.call.mockResolvedValue({ successful: false });

      const result = await service.pollOne(record);

      expect(result.reconciled).toBe(false);
      expect(mockRepository.markReconciled).not.toHaveBeenCalled();
    });

    it('does not attempt on-chain reconciliation when no stellar_tx_hash', async () => {
      const record = makeRecord({ status: Sep24InternalStatus.Pending });

      mockAnchorClient.pollTransaction.mockResolvedValue(
        anchorResponse(Sep24AnchorStatus.Completed, {
          stellar_transaction_id: null,
        }),
      );

      const result = await service.pollOne(record);

      expect(result.reconciled).toBe(false);
      expect(mockHorizonServer.call).not.toHaveBeenCalled();
    });

    it('handles Horizon 404 gracefully and does not mark reconciled', async () => {
      const record = makeRecord({ status: Sep24InternalStatus.Pending });

      mockAnchorClient.pollTransaction.mockResolvedValue(
        anchorResponse(Sep24AnchorStatus.Completed, {
          stellar_transaction_id: 'unknown-tx',
        }),
      );

      const horizonError = Object.assign(new Error('Not found'), {
        response: { status: 404 },
      });

      mockHorizonServer.call.mockRejectedValue(horizonError);

      const result = await service.pollOne(record);

      // Should not throw and should not reconcile
      expect(result.reconciled).toBe(false);
      expect(mockRepository.markReconciled).not.toHaveBeenCalled();
    });
  });

  // ── Full poll cycle summary ───────────────────────────────────────────────

  describe('full cycle', () => {
    it('aggregates counts correctly across multiple transactions', async () => {
      const records = [
        makeRecord({ id: 'r1', anchor_transaction_id: 'a1' }),
        makeRecord({ id: 'r2', anchor_transaction_id: 'a2', status: Sep24InternalStatus.Pending }),
        makeRecord({ id: 'r3', anchor_transaction_id: 'a3', status: Sep24InternalStatus.Pending }),
      ];

      mockRepository.findStuck.mockResolvedValue([]);
      mockRepository.findInFlight.mockResolvedValue(records);

      // r1: in-flight → pending
      // r2: anchor error → failed (terminal)
      // r3: anchor poll fails
      mockAnchorClient.pollTransaction
        .mockResolvedValueOnce(anchorResponse(Sep24AnchorStatus.PendingAnchor))
        .mockResolvedValueOnce(anchorResponse(Sep24AnchorStatus.Error, { message: 'KYC failed' }))
        .mockResolvedValueOnce({
          success: false,
          data: null,
          httpStatus: null,
          error: 'Timeout',
        });

      const summary = await service.runPollCycle();

      expect(summary.processed).toBe(3);
      expect(summary.updated).toBe(2);   // r1 + r2 (terminal is also updated)
      expect(summary.terminal).toBe(1);  // r2
      expect(summary.failed).toBe(1);    // r3 (poll failure)
      expect(summary.stuck).toBe(0);
    });
  });
});
