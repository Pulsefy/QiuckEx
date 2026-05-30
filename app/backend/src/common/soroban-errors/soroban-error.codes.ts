/**
 * Stable API error codes for Soroban contract failures.
 *
 * These codes are part of the public API contract — clients can rely on them
 * for deterministic error handling and UX messaging.
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
  /** Escrow / resource entry not found in contract storage. */
  ESCROW_NOT_FOUND = 'CONTRACT_ESCROW_NOT_FOUND',
  /** Escrow has already been withdrawn or refunded. */
  ESCROW_ALREADY_SETTLED = 'CONTRACT_ESCROW_ALREADY_SETTLED',
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
}
