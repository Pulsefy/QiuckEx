import { Test, TestingModule } from '@nestjs/testing';
import { Horizon } from 'stellar-sdk';

import { AppConfigService } from '../config/app-config.service';
import { SupabaseService } from '../supabase/supabase.service';
import { ReconciliationService } from './reconciliation.service';
import {
  EscrowDbStatus,
  EscrowRecord,
  OnChainState,
  PaymentDbStatus,
  PaymentRecord,
  ReconciliationAction,
} from './types/reconciliation.types';

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

const mockLoadAccount = jest.fn();
const mockTransactionCall = jest.fn();

jest.mock('stellar-sdk', () => {
  return {
    Horizon: {
      Server: jest.fn().mockImplementation(() => ({
        loadAccount: mockLoadAccount,
        transactions: jest.fn().mockReturnValue({
          transaction: jest.fn().mockReturnValue({ call: mockTransactionCall }),
        }),
      })),
    },
  };
});

const mockConfig: Partial<AppConfigService> = {
  network: 'testnet',
  reconciliationBatchSize: 50,
};

const mockSupabase = {
  fetchPendingEscrows: jest.fn(),
  fetchPendingPayments: jest.fn(),
  updateEscrowStatus: jest.fn(),
  updatePaymentStatus: jest.fn(),
  flagIrreconcilableEscrow: jest.fn(),
  flagIrreconcilablePayment: jest.fn(),
};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function makeEscrow(overrides: Partial<EscrowRecord> = {}): EscrowRecord {
  return {
    id: 'escrow-1',
    contract_address: 'GABCDE12345',
    status: EscrowDbStatus.Active,
    amount: '100.0000000',
    asset: 'XLM',
    from_address: 'GFR0M',
    to_address: 'GTOO',
    expires_at: null,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    ...overrides,
  };
}

function makePayment(overrides: Partial<PaymentRecord> = {}): PaymentRecord {
  return {
    id: 'pay-1',
    stellar_tx_hash: 'abc123hash',
    status: PaymentDbStatus.Pending,
    amount: '50.0000000',
    asset: 'XLM',
    from_address: 'GFR0M',
    to_address: 'GTOO',
    memo: null,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

describe('ReconciliationService', () => {
  let service: ReconciliationService;

  beforeEach(async () => {
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ReconciliationService,
        { provide: AppConfigService, useValue: mockConfig },
        { provide: SupabaseService, useValue: mockSupabase },
      ],
    }).compile();

    service = module.get<ReconciliationService>(ReconciliationService);
  });

  // ── Escrow tests ────────────────────────────────────────────────────────────

  describe('escrow reconciliation', () => {
    it('updates DB to claimed when on-chain balance is zero', async () => {
      mockSupabase.fetchPendingEscrows.mockResolvedValue([makeEscrow()]);
      mockSupabase.fetchPendingPayments.mockResolvedValue([]);
      mockLoadAccount.mockResolvedValue({
        balances: [{ asset_type: 'native', balance: '0.0000000' }],
      });
      mockSupabase.updateEscrowStatus.mockResolvedValue(undefined);

      const report = await service.runReconciliation(50);

      expect(report.escrows.updated).toBe(1);
      expect(report.escrows.results[0].action).toBe(ReconciliationAction.Updated);
      expect(report.escrows.results[0].resolvedDbStatus).toBe(EscrowDbStatus.Claimed);
      expect(mockSupabase.updateEscrowStatus).toHaveBeenCalledWith('escrow-1', EscrowDbStatus.Claimed);
    });

    it('updates DB to expired when account exists and expires_at is in the past', async () => {
      const pastDate = new Date(Date.now() - 10_000).toISOString();
      mockSupabase.fetchPendingEscrows.mockResolvedValue([makeEscrow({ expires_at: pastDate })]);
      mockSupabase.fetchPendingPayments.mockResolvedValue([]);
      mockLoadAccount.mockResolvedValue({
        balances: [{ asset_type: 'native', balance: '100.0000000' }],
      });
      mockSupabase.updateEscrowStatus.mockResolvedValue(undefined);

      const report = await service.runReconciliation(50);

      expect(report.escrows.results[0].resolvedDbStatus).toBe(EscrowDbStatus.Expired);
      expect(mockSupabase.updateEscrowStatus).toHaveBeenCalledWith('escrow-1', EscrowDbStatus.Expired);
    });

    it('flags irreconcilable when account does not exist on-chain', async () => {
      mockSupabase.fetchPendingEscrows.mockResolvedValue([makeEscrow()]);
      mockSupabase.fetchPendingPayments.mockResolvedValue([]);
      mockLoadAccount.mockRejectedValue({ response: { status: 404 } });
      mockSupabase.flagIrreconcilableEscrow.mockResolvedValue(undefined);

      const report = await service.runReconciliation(50);

      expect(report.escrows.irreconcilable).toBe(1);
      expect(report.escrows.results[0].irreconcilable).toBe(true);
      expect(report.escrows.results[0].onChainState).toBe(OnChainState.NonExistent);
      expect(mockSupabase.flagIrreconcilableEscrow).toHaveBeenCalledWith('escrow-1', expect.any(String));
    });

    it('is a no-op when escrow is still active on-chain', async () => {
      const futureDate = new Date(Date.now() + 3_600_000).toISOString();
      mockSupabase.fetchPendingEscrows.mockResolvedValue([makeEscrow({ expires_at: futureDate })]);
      mockSupabase.fetchPendingPayments.mockResolvedValue([]);
      mockLoadAccount.mockResolvedValue({
        balances: [{ asset_type: 'native', balance: '100.0000000' }],
      });

      const report = await service.runReconciliation(50);

      expect(report.escrows.noOp).toBe(1);
      expect(mockSupabase.updateEscrowStatus).not.toHaveBeenCalled();
    });

    it('skips record when Horizon is unavailable (non-404 error)', async () => {
      mockSupabase.fetchPendingEscrows.mockResolvedValue([makeEscrow()]);
      mockSupabase.fetchPendingPayments.mockResolvedValue([]);
      mockLoadAccount.mockRejectedValue(new Error('Connection timeout'));

      const report = await service.runReconciliation(50);

      expect(report.escrows.skipped).toBe(1);
      expect(report.escrows.results[0].action).toBe(ReconciliationAction.Skipped);
    });
  });

  // ── Payment tests ───────────────────────────────────────────────────────────

  describe('payment reconciliation', () => {
    it('updates DB to paid when tx is confirmed on-chain', async () => {
      mockSupabase.fetchPendingEscrows.mockResolvedValue([]);
      mockSupabase.fetchPendingPayments.mockResolvedValue([makePayment()]);
      mockTransactionCall.mockResolvedValue({ successful: true });
      mockSupabase.updatePaymentStatus.mockResolvedValue(undefined);

      const report = await service.runReconciliation(50);

      expect(report.payments.updated).toBe(1);
      expect(report.payments.results[0].resolvedDbStatus).toBe(PaymentDbStatus.Paid);
      expect(mockSupabase.updatePaymentStatus).toHaveBeenCalledWith('pay-1', PaymentDbStatus.Paid);
    });

    it('updates DB to failed when tx not found on-chain', async () => {
      mockSupabase.fetchPendingEscrows.mockResolvedValue([]);
      mockSupabase.fetchPendingPayments.mockResolvedValue([makePayment()]);
      mockTransactionCall.mockRejectedValue({ response: { status: 404 } });
      mockSupabase.updatePaymentStatus.mockResolvedValue(undefined);

      const report = await service.runReconciliation(50);

      expect(report.payments.results[0].resolvedDbStatus).toBe(PaymentDbStatus.Failed);
    });

    it('flags irreconcilable when DB is paid but tx not found on-chain', async () => {
      mockSupabase.fetchPendingEscrows.mockResolvedValue([]);
      mockSupabase.fetchPendingPayments.mockResolvedValue([
        makePayment({ status: PaymentDbStatus.Paid }),
      ]);
      mockTransactionCall.mockRejectedValue({ response: { status: 404 } });
      mockSupabase.flagIrreconcilablePayment.mockResolvedValue(undefined);

      const report = await service.runReconciliation(50);

      expect(report.payments.irreconcilable).toBe(1);
      expect(mockSupabase.flagIrreconcilablePayment).toHaveBeenCalledWith('pay-1', expect.any(String));
    });

    it('is a no-op when DB is paid and tx is confirmed', async () => {
      mockSupabase.fetchPendingEscrows.mockResolvedValue([]);
      mockSupabase.fetchPendingPayments.mockResolvedValue([
        makePayment({ status: PaymentDbStatus.Paid }),
      ]);
      mockTransactionCall.mockResolvedValue({ successful: true });

      const report = await service.runReconciliation(50);

      expect(report.payments.noOp).toBe(1);
      expect(mockSupabase.updatePaymentStatus).not.toHaveBeenCalled();
    });
  });

  // ── Report structure ────────────────────────────────────────────────────────

  describe('report structure', () => {
    it('returns a well-formed report with runId, timestamps, and duration', async () => {
      mockSupabase.fetchPendingEscrows.mockResolvedValue([]);
      mockSupabase.fetchPendingPayments.mockResolvedValue([]);

      const report = await service.runReconciliation(50);

      expect(report.runId).toMatch(/^[0-9a-f-]{36}$/);
      expect(report.startedAt).toBeTruthy();
      expect(report.completedAt).toBeTruthy();
      expect(report.durationMs).toBeGreaterThanOrEqual(0);
      expect(report.escrows.results).toBeInstanceOf(Array);
      expect(report.payments.results).toBeInstanceOf(Array);
    });
  });
});
