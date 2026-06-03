import { SorobanErrorCode } from './soroban-error.codes';

export interface MappedSorobanError {
  /** Stable API error code clients can switch on. */
  code: SorobanErrorCode;
  /** Human-readable message safe to surface in UI. */
  message: string;
  /** Raw Soroban error string — included in non-production responses only. */
  technicalError: string;
  /** Optional structured details (error type / code from HostError). */
  details?: Record<string, unknown>;
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
  for (const { pattern, code, message } of ERROR_MAPPINGS) {
    if (pattern.test(rawError)) {
      return { code, message, technicalError: rawError };
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
