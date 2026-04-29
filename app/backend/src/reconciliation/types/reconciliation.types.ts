/**
 * Database-side statuses for escrow records.
 * Mirrors the `status` column in the `escrow_records` table.
 */
export enum EscrowDbStatus {
  Pending = 'pending',
  Active = 'active',
  Claimed = 'claimed',
  Expired = 'expired',
  Cancelled = 'cancelled',
}

/**
 * Database-side statuses for payment records.
 * Mirrors the `status` column in the `payment_records` table.
 */
export enum PaymentDbStatus {
  Pending = 'pending',
  Processing = 'processing',
  Paid = 'paid',
  Failed = 'failed',
}

/**
 * Authoritative on-chain state resolved by querying Horizon.
 */
export enum OnChainState {
  /** Account exists and funds are still held. */
  Active = 'active',
  /** Account has been merged — escrow funds claimed. */
  Claimed = 'claimed',
  /** Account still exists but past its time-bound expiry. */
  Expired = 'expired',
  /** Transaction confirmed on-chain. */
  Confirmed = 'confirmed',
  /** Transaction not found / account does not exist. */
  NonExistent = 'non_existent',
  /** Horizon returned an unexpected error — cannot determine state. */
  Unknown = 'unknown',
}

/** Raw escrow row as returned from Supabase. */
export interface EscrowRecord {
  id: string;
  contract_address: string;  // Stellar account ID acting as escrow
  status: EscrowDbStatus;
  amount: string;
  asset: string;
  from_address: string;
  to_address: string;
  expires_at: string | null;  // ISO timestamp
  created_at: string;
  updated_at: string;
}

/** Raw payment row as returned from Supabase. */
export interface PaymentRecord {
  id: string;
  stellar_tx_hash: string;
  status: PaymentDbStatus;
  amount: string;
  asset: string;
  from_address: string;
  to_address: string;
  memo: string | null;
  created_at: string;
  updated_at: string;
}

/** The outcome of reconciling a single escrow record. */
export interface EscrowReconciliationResult {
  id: string;
  contractAddress: string;
  previousDbStatus: EscrowDbStatus;
  onChainState: OnChainState;
  /** Status actually written to DB after reconciliation. */
  resolvedDbStatus: EscrowDbStatus | null;
  action: ReconciliationAction;
  irreconcilable: boolean;
  irreconcilableReason?: string;
}

/** The outcome of reconciling a single payment record. */
export interface PaymentReconciliationResult {
  id: string;
  txHash: string;
  previousDbStatus: PaymentDbStatus;
  onChainState: OnChainState;
  resolvedDbStatus: PaymentDbStatus | null;
  action: ReconciliationAction;
  irreconcilable: boolean;
  irreconcilableReason?: string;
}

export enum ReconciliationAction {
  /** DB and chain agree — no change needed. */
  NoOp = 'no_op',
  /** DB was stale; updated to match chain. */
  Updated = 'updated',
  /** State cannot be resolved; flagged for manual review. */
  Flagged = 'flagged',
  /** Horizon was unavailable; skipped this record. */
  Skipped = 'skipped',
}

/** Summary report emitted at the end of each reconciliation run. */
export interface ReconciliationReport {
  runId: string;
  startedAt: string;
  completedAt: string;
  durationMs: number;
  escrows: {
    processed: number;
    updated: number;
    noOp: number;
    skipped: number;
    irreconcilable: number;
    results: EscrowReconciliationResult[];
  };
  payments: {
    processed: number;
    updated: number;
    noOp: number;
    skipped: number;
    irreconcilable: number;
    results: PaymentReconciliationResult[];
  };
  /** Comparison of expected vs observed totals for discrepancy detection */
  totalsComparison?: {
    payments: {
      expectedCount: number;
      observedCount: number;
      countDiscrepancy: number;
      expectedTotalAmount: string;
      observedTotalAmount: string;
      amountDiscrepancy: string;
      exceedsThreshold: boolean;
    };
  };
  /** Alert if discrepancies exceed configured threshold */
  alert?: {
    severity: 'warning' | 'critical';
    message: string;
    details: string;
  };
}
