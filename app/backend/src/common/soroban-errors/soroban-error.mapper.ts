import { SorobanErrorCode } from './soroban-error.codes';

/**
 * Secondary reason codes used to disambiguate overloaded contract error
 * variants. The on-chain `QuickexError` enum sits at 49/50 of Soroban's
 * hard cap, so several distinct conditions share a single variant. Clients
 * that branch on `code` should additionally branch on `reason` when present
 * to render condition-specific UI text.
 *
 * See `docs/contract-error-codes.md` for the full overload table.
 */
export enum SorobanErrorReason {
  // admin.rs — shares InvalidAmount / ContractPaused
  UPGRADE_WINDOW_NOT_ACTIVE = 'UPGRADE_WINDOW_NOT_ACTIVE',
  UPGRADE_ALREADY_IN_PROGRESS = 'UPGRADE_ALREADY_IN_PROGRESS',
  // withdraw_fees — shares Overpayment
  FEE_BALANCE_EXCEEDED = 'FEE_BALANCE_EXCEEDED',
  // cleanup_escrow — shares AlreadySpent
  ESCROW_NOT_TERMINAL = 'ESCROW_NOT_TERMINAL',
  // vote_for_dispute — shares InvalidDisputeState
  DISPUTE_NOT_OPEN = 'DISPUTE_NOT_OPEN',
  DISPUTE_VOTING_CLOSED = 'DISPUTE_VOTING_CLOSED',
  DISPUTE_ALREADY_VOTED = 'DISPUTE_ALREADY_VOTED',
  // resolve_dispute_timeout — shares InvalidDisputeState
  DISPUTE_NOT_EXPIRED = 'DISPUTE_NOT_EXPIRED',
  DISPUTE_ALREADY_RESOLVED = 'DISPUTE_ALREADY_RESOLVED',
  DISPUTE_NOT_IN_TIMEOUT = 'DISPUTE_NOT_IN_TIMEOUT',
}

export interface MappedSorobanError {
  /** Stable API error code clients can switch on. */
  code: SorobanErrorCode;
  /** Human-readable message safe to surface in UI. */
  message: string;
  /** Raw Soroban error string — included in non-production responses only. */
  technicalError: string;
  /** Optional structured details (error type / code from HostError). */
  details?: Record<string, unknown>;
  /**
   * Optional secondary reason that disambiguates overloaded error codes.
   * Present only when the underlying contract variant is reused for more
   * than one condition. Clients should prefer `reason` over `code` when
   * rendering condition-specific messages.
   */
  reason?: SorobanErrorReason;
}

/**
 * Each entry maps a regex pattern against the raw Soroban error string to a
 * stable API error code and a user-friendly message.
 *
 * Patterns are tested in order; the first match wins.
 * 
 * STRUCTURED ERRORS (HostError) should come first as they are the most specific.
 */
const ERROR_MAPPINGS: Array<{
  pattern: RegExp;
  code: SorobanErrorCode;
  message: string;
  /**
   * Optional reason to attach when this pattern matches. Used to
   * disambiguate overloaded contract error variants.
   */
  reason?: SorobanErrorReason;
}> = [
  // ── Structured HostErrors (Highest Priority) ─────────────────────────────
  {
    pattern: /HostError.*Error.*Auth.*NotAuthorized/i,
    code: SorobanErrorCode.UNAUTHORIZED,
    message: 'You are not authorised to perform this operation.',
  },
  {
    pattern: /HostError.*Error.*Auth.*InvalidAction/i,
    code: SorobanErrorCode.AUTH_MISSING,
    message: 'A required authorisation entry is missing from the transaction.',
  },
  {
    pattern: /HostError.*Error.*Storage.*MissingValue/i,
    code: SorobanErrorCode.STORAGE_MISSING,
    message: 'A required contract state entry does not exist. The resource may not have been initialised.',
  },
  {
    pattern: /HostError.*Error.*WasmVm.*InvalidAction/i,
    code: SorobanErrorCode.INVALID_INPUT,
    message: 'The smart contract encountered an invalid operation. Check the transaction parameters.',
  },
  {
    pattern: /HostError.*Error.*Value.*InvalidInput/i,
    code: SorobanErrorCode.INVALID_INPUT,
    message: 'One or more input values are invalid for this contract operation.',
  },
  {
    pattern: /HostError.*Error.*Budget.*ExceededLimit/i,
    code: SorobanErrorCode.BUDGET_EXCEEDED,
    message: 'The transaction exceeds Soroban compute limits. Try simplifying the operation.',
  },

  // ── Auth ──────────────────────────────────────────────────────────────────
  {
    pattern: /not\s+authorized/i,
    code: SorobanErrorCode.UNAUTHORIZED,
    message: 'You are not authorised to perform this operation.',
  },

  // ── Contract paused ───────────────────────────────────────────────────────
  {
    pattern: /contract.*paused/i,
    code: SorobanErrorCode.CONTRACT_PAUSED,
    message: 'The contract is currently paused. Please try again later.',
  },
  {
    pattern: /paused/i,
    code: SorobanErrorCode.CONTRACT_PAUSED,
    message: 'The contract is currently paused. Please try again later.',
  },

  // ── Escrow state ──────────────────────────────────────────────────────────
  {
    pattern: /escrow.*not.*found|escrow.*missing/i,
    code: SorobanErrorCode.ESCROW_NOT_FOUND,
    message: 'The escrow entry was not found. It may have already been settled or never created.',
  },
  {
    pattern: /escrow.*already.*settled|already.*withdrawn|already.*refunded/i,
    code: SorobanErrorCode.ESCROW_ALREADY_SETTLED,
    message: 'This escrow has already been settled and cannot be modified.',
  },
  {
    pattern: /escrow.*not.*expired|not.*yet.*expired/i,
    code: SorobanErrorCode.ESCROW_NOT_EXPIRED,
    message: 'The escrow has not yet expired. Refunds are only available after expiry.',
  },
  {
    pattern: /escrow.*expired|payment.*expired/i,
    code: SorobanErrorCode.ESCROW_EXPIRED,
    message: 'The escrow has expired and can no longer be withdrawn.',
  },

  // ── Storage ───────────────────────────────────────────────────────────────
  {
    pattern: /restore.*required|entry.*expired.*restore/i,
    code: SorobanErrorCode.RESTORE_REQUIRED,
    message: 'Some contract state entries have expired and must be restored before this transaction can proceed.',
  },

  // ── Balance ───────────────────────────────────────────────────────────────
  {
    pattern: /insufficient.*balance|balance.*insufficient/i,
    code: SorobanErrorCode.INSUFFICIENT_BALANCE,
    message: 'Insufficient balance to complete this operation.',
  },
  {
    pattern: /invalid.*amount|amount.*invalid|amount.*zero|zero.*amount/i,
    code: SorobanErrorCode.INVALID_AMOUNT,
    message: 'The amount provided is invalid. It must be a positive non-zero value.',
  },

  // ── Overloaded variants (disambiguated via `reason`) ─────────────────────
  // admin.rs: `InvalidAmount` is reused for "upgrade window not active".
  {
    pattern: /upgrade.*window.*not.*active|window.*not.*active/i,
    code: SorobanErrorCode.INVALID_AMOUNT,
    message: 'The upgrade window is not currently active. Upgrades are only allowed during a scheduled window.',
    reason: SorobanErrorReason.UPGRADE_WINDOW_NOT_ACTIVE,
  },
  // admin.rs: `ContractPaused` is reused for "upgrade already in progress".
  {
    pattern: /upgrade.*already.*in.*progress|already.*in.*progress/i,
    code: SorobanErrorCode.CONTRACT_PAUSED,
    message: 'An upgrade is already in progress. Wait for it to complete before starting another.',
    reason: SorobanErrorReason.UPGRADE_ALREADY_IN_PROGRESS,
  },
  // withdraw_fees: `Overpayment` is reused for "amount exceeds accrued fee balance".
  {
    pattern: /amount.*exceeds.*accrued.*fee|exceeds.*fee.*balance|fee.*balance.*exceeded/i,
    code: SorobanErrorCode.OVERPAYMENT,
    message: 'The requested amount exceeds the accrued fee balance available for withdrawal.',
    reason: SorobanErrorReason.FEE_BALANCE_EXCEEDED,
  },
  // cleanup_escrow: `AlreadySpent` is reused for any non-terminal state.
  {
    pattern: /escrow.*not.*terminal|non[- ]?terminal.*escrow|escrow.*still.*active/i,
    code: SorobanErrorCode.ALREADY_SPENT,
    message: 'The escrow is not in a terminal state and cannot be cleaned up yet.',
    reason: SorobanErrorReason.ESCROW_NOT_TERMINAL,
  },
  // vote_for_dispute: `InvalidDisputeState` is reused for three conditions.
  {
    pattern: /dispute.*not.*open|voting.*not.*open/i,
    code: SorobanErrorCode.INVALID_DISPUTE_STATE,
    message: 'The dispute is not open for voting.',
    reason: SorobanErrorReason.DISPUTE_NOT_OPEN,
  },
  {
    pattern: /dispute.*voting.*closed|voting.*period.*ended/i,
    code: SorobanErrorCode.INVALID_DISPUTE_STATE,
    message: 'The voting period for this dispute has closed.',
    reason: SorobanErrorReason.DISPUTE_VOTING_CLOSED,
  },
  {
    pattern: /dispute.*already.*voted|already.*voted.*dispute/i,
    code: SorobanErrorCode.INVALID_DISPUTE_STATE,
    message: 'You have already voted on this dispute.',
    reason: SorobanErrorReason.DISPUTE_ALREADY_VOTED,
  },
  // resolve_dispute_timeout: `InvalidDisputeState` is reused for three conditions.
  {
    pattern: /dispute.*not.*expired|timeout.*not.*reached/i,
    code: SorobanErrorCode.INVALID_DISPUTE_STATE,
    message: 'The dispute timeout has not yet expired.',
    reason: SorobanErrorReason.DISPUTE_NOT_EXPIRED,
  },
  {
    pattern: /dispute.*already.*resolved|already.*resolved.*dispute/i,
    code: SorobanErrorCode.INVALID_DISPUTE_STATE,
    message: 'The dispute has already been resolved.',
    reason: SorobanErrorReason.DISPUTE_ALREADY_RESOLVED,
  },
  {
    pattern: /dispute.*not.*in.*timeout|not.*in.*timeout.*dispute/i,
    code: SorobanErrorCode.INVALID_DISPUTE_STATE,
    message: 'The dispute is not currently in the timeout resolution phase.',
    reason: SorobanErrorReason.DISPUTE_NOT_IN_TIMEOUT,
  },

  // ── Admin ─────────────────────────────────────────────────────────────────
  {
    pattern: /not.*admin|caller.*not.*admin/i,
    code: SorobanErrorCode.NOT_ADMIN,
    message: 'Only the contract admin can perform this operation.',
  },
  {
    pattern: /invalid.*admin|admin.*invalid/i,
    code: SorobanErrorCode.INVALID_ADMIN,
    message: 'The admin address provided is invalid.',
  },

  // ── Version mismatch ──────────────────────────────────────────────────────
  {
    pattern: /version.*mismatch|schema.*version|unsupported.*version/i,
    code: SorobanErrorCode.VERSION_MISMATCH,
    message: 'The contract version is not compatible with this operation.',
  },
  {
    pattern: /invalid.*wasm|wasm.*invalid/i,
    code: SorobanErrorCode.INVALID_WASM_HASH,
    message: 'The WASM hash provided for the contract upgrade is invalid.',
  },

  // ── Input / params ────────────────────────────────────────────────────────
  {
    pattern: /account.*does not exist|account.*not.*found/i,
    code: SorobanErrorCode.NOT_FOUND,
    message: 'The source account does not exist on the network. Ensure it is funded and activated.',
  },
  {
    pattern: /contract.*does not exist|contract.*not.*found/i,
    code: SorobanErrorCode.NOT_FOUND,
    message: 'The specified contract does not exist on this network. Check the contract ID.',
  },

  // ── Resource limits ───────────────────────────────────────────────────────
  {
    pattern: /transaction.*too large/i,
    code: SorobanErrorCode.BUDGET_EXCEEDED,
    message: 'The transaction is too large. Consider reducing the complexity of the operation.',
  },
];

/**
 * Maps a raw Soroban / simulation error string to a stable {@link MappedSorobanError}.
 *
 * Strategy:
 * 1. Test each pattern in order; return the first match.
 * 2. If no pattern matches but a HostError code is present, extract the type
 *    and code for structured details and return UNKNOWN.
 * 3. Fall back to a generic UNKNOWN response so clients always get a stable code.
 *
 * The `technicalError` field always carries the raw string for server-side
 * logging; it should be omitted from production API responses.
 */
export function mapSorobanError(rawError: string): MappedSorobanError {
  for (const { pattern, code, message, reason } of ERROR_MAPPINGS) {
    if (pattern.test(rawError)) {
      return { code, message, technicalError: rawError, ...(reason ? { reason } : {}) };
    }
  }

  // Parse structured HostError codes even when no pattern matched.
  const hostErrorMatch = rawError.match(/Error\((\w+),\s*(\w+)\)/);
  if (hostErrorMatch) {
    return {
      code: SorobanErrorCode.UNKNOWN,
      message: 'An unexpected contract error occurred. Please verify the transaction parameters and try again.',
      technicalError: rawError,
      details: {
        errorType: hostErrorMatch[1],
        errorCode: hostErrorMatch[2],
      },
    };
  }

  return {
    code: SorobanErrorCode.UNKNOWN,
    message: 'An unexpected contract error occurred. Please try again or contact support.',
    technicalError: rawError,
  };
}
