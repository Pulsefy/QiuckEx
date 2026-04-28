/**
 * Auto-Match Engine – Domain Types
 *
 * Models the full lifecycle of automatically matching an incoming Stellar
 * payment to an open QuickEx payment link:
 *
 *   IncomingTransaction  ──▶  score against PaymentLink[]
 *                         ──▶  MatchResult (AutoMatch | ReviewRequired | Unmatched)
 *                         ──▶  apply state update or queue for operator review
 */

// ─── Payment Links ────────────────────────────────────────────────────────────

/** Mirrors the `payment_links` table row returned from Supabase. */
export interface PaymentLink {
  id: string;
  owner_public_key: string;
  destination_public_key: string;
  /** Decimal string, e.g. "10.5000000". */
  amount: string;
  asset_code: string;
  asset_issuer: string | null;
  memo: string | null;
  /** One of: "text" | "id" | "hash" | "return" | "none". */
  memo_type: string;
  reference_id: string | null;
  status: PaymentLinkStatus;
  expires_at: string | null;
  matched_tx_hash: string | null;
  matched_at: string | null;
  match_confidence: number | null;
  created_at: string;
  updated_at: string;
}

export enum PaymentLinkStatus {
  Open = 'open',
  Paid = 'paid',
  Expired = 'expired',
  Cancelled = 'cancelled',
}

// ─── Incoming Transactions ────────────────────────────────────────────────────

/**
 * Normalised on-chain payment operation from Horizon.
 * Built by the auto-match engine from raw Horizon API responses.
 */
export interface IncomingTransaction {
  txHash: string;
  ledger: number;
  sourceAccount: string;
  destinationAccount: string;
  /** Decimal string as returned by Horizon, e.g. "25.0000000". */
  amount: string;
  assetCode: string;
  assetIssuer: string | null;
  memo: string | null;
  memoType: string | null;
  /** ISO-8601 timestamp from Horizon. */
  occurredAt: string;
}

// ─── Scoring ──────────────────────────────────────────────────────────────────

/**
 * Per-signal breakdown explaining how a confidence score was reached for a
 * single (transaction, link) candidate pair.
 */
export interface MatchScoreBreakdown {
  /** Both the transaction and the link carry a memo value. */
  memoPresent: boolean;
  /** The transaction memo equals the link memo. */
  memoMatches: boolean;
  /**
   * Only one open payment link has this memo across the current candidate set.
   * When true, a memo match carries maximum confidence.
   */
  memoIsUnique: boolean;
  /** Transaction amount equals the link amount within floating-point epsilon. */
  amountExact: boolean;
  /** Transaction amount is within AMOUNT_TOLERANCE_PCT of the link amount. */
  amountWithinTolerance: boolean;
  /** Asset code and issuer match between the transaction and the link. */
  assetMatches: boolean;
}

/** Scored result for one (transaction, link) candidate pair. */
export interface MatchScore {
  /** Overall confidence: 0–100. */
  confidence: number;
  breakdown: MatchScoreBreakdown;
}

// ─── Match Decisions ──────────────────────────────────────────────────────────

export enum MatchDecision {
  /**
   * confidence ≥ AUTO_MATCH_THRESHOLD.
   * The engine marks the link as "paid" and fires a webhook automatically.
   */
  AutoMatch = 'auto_match',
  /**
   * confidence ≥ REVIEW_THRESHOLD but < AUTO_MATCH_THRESHOLD.
   * The transaction is queued in `unmatched_transactions` for operator review.
   */
  ReviewRequired = 'review_required',
  /**
   * No candidate scored above the minimum threshold.
   * The transaction is stored as unmatched with no suggested link.
   */
  Unmatched = 'unmatched',
}

/** Final outcome for a single incoming transaction after processing. */
export interface MatchResult {
  transaction: IncomingTransaction;
  decision: MatchDecision;
  /** Best candidate link, or null when no candidates scored above zero. */
  bestLink: PaymentLink | null;
  /** Score of the best candidate, or null when unmatched. */
  bestScore: MatchScore | null;
  /** All candidates with positive scores, sorted by confidence descending. */
  candidates: Array<{ link: PaymentLink; score: MatchScore }>;
  /** ISO-8601 timestamp of when this result was produced. */
  processedAt: string;
}

// ─── Unmatched Queue ──────────────────────────────────────────────────────────

/** Mirrors the `unmatched_transactions` table row returned from Supabase. */
export interface UnmatchedTransaction {
  id: string;
  tx_hash: string;
  ledger: number | null;
  source_account: string;
  destination_account: string;
  amount: string;
  asset_code: string;
  asset_issuer: string | null;
  memo: string | null;
  memo_type: string | null;
  occurred_at: string;
  ingested_at: string;
  status: UnmatchedStatus;
  best_candidate_link_id: string | null;
  best_confidence: number | null;
  resolved_by: string | null;
  resolved_at: string | null;
  resolution_note: string | null;
}

export enum UnmatchedStatus {
  Pending = 'pending',
  Resolved = 'resolved',
  Dismissed = 'dismissed',
}

// ─── Webhook / Event Payload ───────────────────────────────────────────────────

/**
 * Emitted on EventEmitter2 as `auto_reconciliation.succeeded` after the engine
 * successfully auto-matches a transaction to a payment link.
 */
export interface AutoReconciliationSucceededPayload {
  linkId: string;
  ownerPublicKey: string;
  txHash: string;
  amount: string;
  assetCode: string;
  /** 0–100 confidence score that triggered the auto-match. */
  confidence: number;
  /** ISO-8601 timestamp when the match was applied. */
  matchedAt: string;
}
