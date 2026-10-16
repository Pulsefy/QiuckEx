/**
 * Stable API error codes for Soroban contract failures.
 *
 * These codes are part of the public API contract — clients can rely on them
 * for deterministic error handling and UX messaging.
 *
 * Overloaded codes: the on-chain QuickexError enum is at 49/50 of Soroban's
 * variant cap, so several distinct conditions intentionally share one code.
 * Clients MUST disambiguate using the optional `reason` field returned
 * alongside the code (see SorobanErrorReason below) rather than branching on
 * the code alone. Overloaded codes and their meanings:
 *
 *   CONTRACT_INVALID_AMOUNT   → zero/negative amount | upgrade window not active
 *   CONTRACT_PAUSED           → contract paused      | upgrade already in progress
 *   CONTRACT_OVERPAYMENT      → overpayment         | amount exceeds accrued fee balance
 *   CONTRACT_ESCROW_ALREADY_SETTLED → already spent | escrow in any non-terminal state
 *   CONTRACT_INVALID_DISPUTE_STATE  → invalid dispute state (vote_for_dispute: 3 conditions)
 *                                   | invalid dispute state (resolve_dispute_timeout: 3 conditions)
 *
 * Migration/compat note: error codes are part of the public API. Any future
 * renumbering or removal of a variant is a breaking change and requires a
 * documented deprecation window. The `reason` field is additive and optional;
 * existing clients that branch only on `code` keep working but may show
 * generic messaging for overloaded codes.
 *
 * Grouped by domain: Auth, Contract State, Balance, Admin, Version, Generic.
 */
export enum SorobanErrorCode {
  // ── Auth ──────────────────────────────────────────────────────────────────
  /** Caller is not authorised to perform this operation. */
  UNAUTHORIZED = 'CONTRACT_UNAUTHORIZED',
  /** Required auth entry is missing from the transaction. */
  AUTH_MISSING = 'CONTRACT_AUTH_MISSING',

  // ── Contract state ────────────────────────────────────────────────────────
  /** Contract is paused; all mutating operations are blocked. */
  CONTRACT_PAUSED = 'CONTRACT_PAUSED',
  /** Contract write operations are temporarily disabled by the server. */
  CONTRACT_WRITES_DISABLED = 'CONTRACT_WRITES_DISABLED',
  /** Escrow / resource entry not found in contract storage. */
  ESCROW_NOT_FOUND = 'CONTRACT_ESCROW_NOT_FOUND',
  /** Escrow has already been withdrawn or refunded. */
  ESCROW_ALREADY_SETTLED = 'CONTRACT_ESCROW_ALREADY_SETTLED',
  /**
   * Overloaded: escrow already spent, OR escrow is in any non-terminal state
   * (cleanup_escrow). Disambiguate via SorobanErrorReason.
   */
  ESCROW_NOT_TERMINAL = 'CONTRACT_ESCROW_ALREADY_SETTLED',
  /** Escrow has not yet expired; refund is not allowed. */
  ESCROW_NOT_EXPIRED = 'CONTRACT_ESCROW_NOT_EXPIRED',
  /** Escrow has expired; withdrawal is no longer allowed. */
  ESCROW_EXPIRED = 'CONTRACT_ESCROW_EXPIRED',
  /** Required contract storage entry is missing (MissingValue). */
  STORAGE_MISSING = 'CONTRACT_STORAGE_MISSING',
  /** Ledger entry has expired and must be restored before use. */
  RESTORE_REQUIRED = 'CONTRACT_RESTORE_REQUIRED',

  // ── Balance ───────────────────────────────────────────────────────────────
  /** Account or escrow has insufficient token balance. */
  INSUFFICIENT_BALANCE = 'CONTRACT_INSUFFICIENT_BALANCE',
  /** Amount provided is zero or negative. */
  INVALID_AMOUNT = 'CONTRACT_INVALID_AMOUNT',
  /**
   * Overloaded: amount exceeds accrued fee balance (withdraw_fees), OR
   * upgrade window is not active (admin). Disambiguate via SorobanErrorReason.
   */
  OVERPAYMENT = 'CONTRACT_OVERPAYMENT',
  /** Overloaded: invalid dispute state for vote_for_dispute / resolve_dispute_timeout. */
  INVALID_DISPUTE_STATE = 'CONTRACT_INVALID_DISPUTE_STATE',

  // ── Version / upgrade ─────────────────────────────────────────────────────
  /** Contract schema version is not supported by this client. */
  VERSION_MISMATCH = 'CONTRACT_VERSION_MISMATCH',
  /** WASM hash provided for upgrade is invalid. */
  INVALID_WASM_HASH = 'CONTRACT_INVALID_WASM_HASH',

  // ── Admin ─────────────────────────────────────────────────────────────────
  /** Caller is not the contract admin. */
  NOT_ADMIN = 'CONTRACT_NOT_ADMIN',
  /** Admin address provided is invalid. */
  INVALID_ADMIN = 'CONTRACT_INVALID_ADMIN',

  // ── Input / params ────────────────────────────────────────────────────────
  /** One or more input values are invalid for this contract call. */
  INVALID_INPUT = 'CONTRACT_INVALID_INPUT',
  /** Contract or account does not exist on the network. */
  NOT_FOUND = 'CONTRACT_NOT_FOUND',

  // ── Resource limits ───────────────────────────────────────────────────────
  /** Transaction exceeds Soroban compute budget. */
  BUDGET_EXCEEDED = 'CONTRACT_BUDGET_EXCEEDED',

  // ── Generic fallback ──────────────────────────────────────────────────────
  /** An unexpected contract error occurred. */
  UNKNOWN = 'CONTRACT_UNKNOWN_ERROR',

  // ── Indexer Lag Guard ─────────────────────────────────────────────────────
  /** Indexer is lagging too far behind the network; risky operations are blocked. */
  INDEXER_LAGGING = 'INDEXER_LAGGING',
}

/**
 * Secondary discriminator returned alongside SorobanErrorCode to disambiguate
 * overloaded codes. Optional and additive — clients that ignore it continue to
 * receive the shared code and must fall back to generic messaging.
 */
export enum SorobanErrorReason {
  /** admin.rs: upgrade window not active. */
  UPGRADE_WINDOW_NOT_ACTIVE = 'UPGRADE_WINDOW_NOT_ACTIVE',
  /** admin.rs: upgrade already in progress. */
  UPGRADE_ALREADY_IN_PROGRESS = 'UPGRADE_ALREADY_IN_PROGRESS',
  /** withdraw_fees: amount exceeds accrued fee balance. */
  FEE_BALANCE_EXCEEDED = 'FEE_BALANCE_EXCEEDED',
  /** cleanup_escrow: escrow is in a non-terminal state. */
  ESCROW_NOT_TERMINAL = 'ESCROW_NOT_TERMINAL',
  /** vote_for_dispute / resolve_dispute_timeout: invalid dispute state. */
  INVALID_DISPUTE_STATE = 'INVALID_DISPUTE_STATE',
}
