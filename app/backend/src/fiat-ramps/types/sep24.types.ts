/**
 * SEP-24 Domain Types
 *
 * Covers the full lifecycle of a hosted-interactive deposit or withdrawal
 * transaction as defined by the Stellar Ecosystem Proposal 24 specification:
 * https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0024.md
 */

// ─── Anchor-side statuses (as reported by the anchor's /transaction endpoint) ──

/**
 * All statuses that can be returned by an anchor's SEP-24 GET /transaction
 * response.  The anchor may return additional custom statuses — those are
 * represented by Sep24AnchorStatus.Unknown to allow forward-compatibility.
 */
export enum Sep24AnchorStatus {
  /** User action is required (e.g. complete KYC). */
  IncompleteInfo = 'incomplete',
  /** Anchor is waiting for the user to initiate the Stellar transfer. */
  PendingUserTransferStart = 'pending_user_transfer_start',
  /** Stellar transfer received, anchor processing. */
  PendingAnchor = 'pending_anchor',
  /** Anchor has submitted the fiat transfer. */
  PendingExternal = 'pending_external',
  /** Anchor waiting for the fiat transfer to be acknowledged. */
  PendingReceivingAnchor = 'pending_receiving_anchor',
  /** Pending trust line or other user-side setup. */
  PendingTrust = 'pending_trust',
  /** Anchor waiting for user action after initial KYC step. */
  PendingUser = 'pending_user',
  /** Transaction is done; no errors. */
  Completed = 'completed',
  /** Transaction is refunded. */
  Refunded = 'refunded',
  /** Transaction expired before completion. */
  Expired = 'expired',
  /** An error occurred and the transaction needs user attention. */
  Error = 'error',
  /** An error occurred on the anchor side. */
  AnchorError = 'anchor_error',
  /** Status returned by the anchor that is not in the known set. */
  Unknown = 'unknown',
}

/** Statuses that represent a final, non-retriable outcome. */
export const TERMINAL_ANCHOR_STATUSES: ReadonlySet<Sep24AnchorStatus> = new Set([
  Sep24AnchorStatus.Completed,
  Sep24AnchorStatus.Refunded,
  Sep24AnchorStatus.Expired,
  Sep24AnchorStatus.Error,
  Sep24AnchorStatus.AnchorError,
]);

/** Statuses that mean the anchor is still processing (in-flight). */
export const IN_FLIGHT_ANCHOR_STATUSES: ReadonlySet<Sep24AnchorStatus> = new Set([
  Sep24AnchorStatus.IncompleteInfo,
  Sep24AnchorStatus.PendingUserTransferStart,
  Sep24AnchorStatus.PendingAnchor,
  Sep24AnchorStatus.PendingExternal,
  Sep24AnchorStatus.PendingReceivingAnchor,
  Sep24AnchorStatus.PendingTrust,
  Sep24AnchorStatus.PendingUser,
]);

// ─── Internal DB statuses ──────────────────────────────────────────────────────

/**
 * Internal status stored in the `sep24_transactions` table.
 * Maps loosely from Sep24AnchorStatus but is not 1:1 — we collapse several
 * anchor in-flight statuses into a single `pending` internal status.
 */
export enum Sep24InternalStatus {
  /** Transaction initiated; awaiting first anchor poll. */
  Initiated = 'initiated',
  /** Anchor is still processing (any in-flight anchor status). */
  Pending = 'pending',
  /** Transaction completed successfully; Stellar side confirmed. */
  Completed = 'completed',
  /** Transaction was refunded by the anchor. */
  Refunded = 'refunded',
  /** Transaction expired before completion. */
  Expired = 'expired',
  /** Terminal error on the anchor or user side. */
  Failed = 'failed',
  /** Confirmed on-chain and reconciled against a payment record. */
  Reconciled = 'reconciled',
  /** Stuck past the configurable threshold — flagged for operator review. */
  StuckFlagged = 'stuck_flagged',
}

// ─── Raw DB row ────────────────────────────────────────────────────────────────

/**
 * Mirrors the `sep24_transactions` Supabase table row.
 */
export interface Sep24TransactionRecord {
  /** UUID primary key. */
  id: string;
  /** SEP-24 transaction ID assigned by the anchor. */
  anchor_transaction_id: string;
  /** Stellar anchor domain (e.g. "moneygram.stellar.org"). */
  anchor_domain: string;
  /** Whether this is a deposit or withdrawal. */
  type: 'deposit' | 'withdrawal';
  /** Internal status (see Sep24InternalStatus). */
  status: Sep24InternalStatus;
  /** Raw anchor-reported status string (preserved for debugging). */
  anchor_status: string | null;
  /** On-chain Stellar transaction hash once settled (may be null). */
  stellar_tx_hash: string | null;
  /** Amount as a decimal string. */
  amount: string;
  /** Asset code (e.g. "USDC"). */
  asset_code: string;
  /** Asset issuer public key (null for native XLM). */
  asset_issuer: string | null;
  /** Stellar account that initiated the SEP-24 flow. */
  user_account: string;
  /** URL returned by the anchor for the hosted interactive UI. */
  interactive_url: string | null;
  /** ISO-8601 timestamp when the transaction was created in our system. */
  created_at: string;
  /** ISO-8601 timestamp of last status update. */
  updated_at: string;
  /** ISO-8601 timestamp of the last successful poll against the anchor. */
  last_polled_at: string | null;
  /** Running count of consecutive poll failures (used for backoff). */
  poll_failure_count: number;
  /** Human-readable failure or stuck reason (null if healthy). */
  failure_reason: string | null;
  /** ISO-8601 timestamp when the transaction entered a terminal state. */
  terminal_at: string | null;
}

// ─── Anchor HTTP response shape ────────────────────────────────────────────────

/**
 * Minimal shape of the anchor's GET /sep24/transaction response.
 * Only fields needed for polling are represented; the anchor may return
 * additional fields that we ignore.
 */
export interface AnchorTransactionResponse {
  transaction: {
    id: string;
    kind: 'deposit' | 'withdrawal';
    status: string;
    status_eta?: number | null;
    more_info_url?: string | null;
    stellar_transaction_id?: string | null;
    amount_in?: string | null;
    amount_out?: string | null;
    amount_fee?: string | null;
    message?: string | null;
    refunded?: boolean;
    from?: string | null;
    to?: string | null;
    started_at?: string;
    completed_at?: string | null;
  };
}

// ─── Poll result ────────────────────────────────────────────────────────────────

/**
 * Outcome of polling a single SEP-24 transaction against the anchor.
 */
export interface Sep24PollResult {
  transactionId: string;
  anchorTransactionId: string;
  previousInternalStatus: Sep24InternalStatus;
  anchorStatus: Sep24AnchorStatus;
  newInternalStatus: Sep24InternalStatus;
  stellarTxHash: string | null;
  terminal: boolean;
  stuck: boolean;
  /** Whether the on-chain activity was matched to the reconciliation module. */
  reconciled: boolean;
  errorMessage: string | null;
}

// ─── Configuration ──────────────────────────────────────────────────────────────

/**
 * Configuration values injected into the polling service.
 * All values have sensible defaults; override via environment variables.
 */
export interface Sep24PollingConfig {
  /**
   * Minimum age of a pending transaction (ms) before it is considered stuck.
   * Default: 3 600 000 ms (1 hour).
   */
  stuckThresholdMs: number;
  /**
   * Maximum number of consecutive poll failures before a transaction is
   * flagged as stuck and removed from the poll queue.
   * Default: 5.
   */
  maxPollFailures: number;
  /**
   * Maximum number of transactions to process per poll cycle.
   * Default: 50.
   */
  batchSize: number;
}
