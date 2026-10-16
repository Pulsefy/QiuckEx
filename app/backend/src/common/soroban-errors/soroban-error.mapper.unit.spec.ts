import { mapSorobanError } from './soroban-error.mapper';
import { SorobanErrorCode } from './soroban-error.codes';
import { OverloadedErrorReason } from './soroban-error.reasons';

describe('mapSorobanError', () => {
  // ── Auth ────────────────────────────────────────────────────────────────

  it('maps Auth.NotAuthorized HostError to UNAUTHORIZED', () => {
    const raw = 'HostError: Error(Auth, NotAuthorized)';
    const result = mapSorobanError(raw);
    expect(result.code).toBe(SorobanErrorCode.UNAUTHORIZED);
    expect(result.technicalError).toBe(raw);
    expect(result.message).toBeTruthy();
  });

  it('maps "not authorized" plain text to UNAUTHORIZED', () => {
    const result = mapSorobanError('caller is not authorized to withdraw');
    expect(result.code).toBe(SorobanErrorCode.UNAUTHORIZED);
  });

  it('maps Auth.InvalidAction HostError to AUTH_MISSING', () => {
    const result = mapSorobanError('HostError: Error(Auth, InvalidAction)');
    expect(result.code).toBe(SorobanErrorCode.AUTH_MISSING);
  });

  // ── Contract paused ─────────────────────────────────────────────────────

  it('maps "contract paused" to CONTRACT_PAUSED', () => {
    const result = mapSorobanError('Error: contract is paused');
    expect(result.code).toBe(SorobanErrorCode.CONTRACT_PAUSED);
  });

  it('maps bare "paused" to CONTRACT_PAUSED', () => {
    const result = mapSorobanError('operation rejected: paused');
    expect(result.code).toBe(SorobanErrorCode.CONTRACT_PAUSED);
  });

  // ── Overloaded error codes ──────────────────────────────────────────────
  // The QuickexError enum sits at 49/50 of Soroban's variant cap, so several
  // conditions intentionally share a code. Each distinct condition must still
  // be distinguishable via `reason` so clients can render accurate UI text.
  // These tests pin the (code, reason) pair against accidental renumbering.

  it('maps "upgrade window not active" to CONTRACT_PAUSED with UPGRADE_WINDOW_NOT_ACTIVE reason', () => {
    const result = mapSorobanError('upgrade window not active');
    expect(result.code).toBe(SorobanErrorCode.CONTRACT_PAUSED);
    expect(result.reason).toBe(OverloadedErrorReason.UPGRADE_WINDOW_NOT_ACTIVE);
  });

  it('maps "upgrade already in progress" to CONTRACT_PAUSED with UPGRADE_ALREADY_IN_PROGRESS reason', () => {
    const result = mapSorobanError('upgrade already in progress');
    expect(result.code).toBe(SorobanErrorCode.CONTRACT_PAUSED);
    expect(result.reason).toBe(OverloadedErrorReason.UPGRADE_ALREADY_IN_PROGRESS);
  });

  it('maps "amount exceeds accrued fee balance" to OVERPAYMENT with FEE_BALANCE_EXCEEDED reason', () => {
    const result = mapSorobanError('amount exceeds accrued fee balance');
    expect(result.code).toBe(SorobanErrorCode.OVERPAYMENT);
    expect(result.reason).toBe(OverloadedErrorReason.FEE_BALANCE_EXCEEDED);
  });

  it('maps "escrow not in terminal state" to ALREADY_SPENT with NON_TERMINAL_STATE reason', () => {
    const result = mapSorobanError('escrow not in terminal state');
    expect(result.code).toBe(SorobanErrorCode.ALREADY_SPENT);
    expect(result.reason).toBe(OverloadedErrorReason.NON_TERMINAL_STATE);
  });

  it('maps "dispute already voted" to INVALID_DISPUTE_STATE with DISPUTE_ALREADY_VOTED reason', () => {
    const result = mapSorobanError('dispute already voted');
    expect(result.code).toBe(SorobanErrorCode.INVALID_DISPUTE_STATE);
    expect(result.reason).toBe(OverloadedErrorReason.DISPUTE_ALREADY_VOTED);
  });

  it('maps "dispute not open" to INVALID_DISPUTE_STATE with DISPUTE_NOT_OPEN reason', () => {
    const result = mapSorobanError('dispute not open');
    expect(result.code).toBe(SorobanErrorCode.INVALID_DISPUTE_STATE);
    expect(result.reason).toBe(OverloadedErrorReason.DISPUTE_NOT_OPEN);
  });

  it('maps "dispute timeout not reached" to INVALID_DISPUTE_STATE with DISPUTE_TIMEOUT_NOT_REACHED reason', () => {
    const result = mapSorobanError('dispute timeout not reached');
    expect(result.code).toBe(SorobanErrorCode.INVALID_DISPUTE_STATE);
    expect(result.reason).toBe(OverloadedErrorReason.DISPUTE_TIMEOUT_NOT_REACHED);
  });

  it('leaves reason undefined for non-overloaded errors', () => {
    const result = mapSorobanError('insufficient balance for transfer');
    expect(result.code).toBe(SorobanErrorCode.INSUFFICIENT_BALANCE);
    expect(result.reason).toBeUndefined();
  });

  // ── Escrow state ────────────────────────────────────────────────────────

  it('maps "escrow not found" to ESCROW_NOT_FOUND', () => {
    const result = mapSorobanError('escrow not found for commitment 0xabc');
    expect(result.code).toBe(SorobanErrorCode.ESCROW_NOT_FOUND);
  });

  it('maps "already withdrawn" to ESCROW_ALREADY_SETTLED', () => {
    const result = mapSorobanError('escrow already withdrawn');
    expect(result.code).toBe(SorobanErrorCode.ESCROW_ALREADY_SETTLED);
  });

  it('maps "already refunded" to ESCROW_ALREADY_SETTLED', () => {
    const result = mapSorobanError('escrow already refunded');
    expect(result.code).toBe(SorobanErrorCode.ESCROW_ALREADY_SETTLED);
  });

  it('maps "escrow not expired" to ESCROW_NOT_EXPIRED', () => {
    const result = mapSorobanError('escrow not yet expired');
    expect(result.code).toBe(SorobanErrorCode.ESCROW_NOT_EXPIRED);
  });

  it('maps "escrow expired" to ESCROW_EXPIRED', () => {
    const result = mapSorobanError('escrow expired, withdrawal not allowed');
    expect(result.code).toBe(SorobanErrorCode.ESCROW_EXPIRED);
  });

  // ── Storage ─────────────────────────────────────────────────────────────

  it('maps Storage.MissingValue HostError to STORAGE_MISSING', () => {
    const result = mapSorobanError('HostError: Error(Storage, MissingValue)');
    expect(result.code).toBe(SorobanErrorCode.STORAGE_MISSING);
  });

  it('maps "restore required" to RESTORE_REQUIRED', () => {
    const result = mapSorobanError('restore required before proceeding');
    expect(result.code).toBe(SorobanErrorCode.RESTORE_REQUIRED);
  });

  // ── Balance ─────────────────────────────────────────────────────────────

  it('maps "insufficient balance" to INSUFFICIENT_BALANCE', () => {
    const result = mapSorobanError('insufficient balance for transfer');
    expect(result.code).toBe(SorobanErrorCode.INSUFFICIENT_BALANCE);
  });

  it('maps "balance insufficient" to INSUFFICIENT_BALANCE', () => {
    const result = mapSorobanError('balance insufficient');
    expect(result.code).toBe(SorobanErrorCode.INSUFFICIENT_BALANCE);
  });

  it('maps "invalid amount" to INVALID_AMOUNT', () => {
    const result = mapSorobanError('invalid amount: must be positive');
    expect(result.code).toBe(SorobanErrorCode.INVALID_AMOUNT);
  });

  it('maps "zero amount" to INVALID_AMOUNT', () => {
    const result = mapSorobanError('zero amount not allowed');
    expect(result.code).toBe(SorobanErrorCode.INVALID_AMOUNT);
  });

  // ── Version mismatch ────────────────────────────────────────────────────

  it('maps "version mismatch" to VERSION_MISMATCH', () => {
    const result = mapSorobanError('schema version mismatch: expected 2, got 3');
    expect(result.code).toBe(SorobanErrorCode.VERSION_MISMATCH);
  });

  it('maps "unsupported version" to VERSION_MISMATCH', () => {
    const result = mapSorobanError('unsupported version 5');
    expect(result.code).toBe(SorobanErrorCode.VERSION_MISMATCH);
  });

  it('maps "invalid wasm" to INVALID_WASM_HASH', () => {
    const result = mapSorobanError('invalid wasm hash provided');
    expect(result.code).toBe(SorobanErrorCode.INVALID_WASM_HASH);
  });

  // ── Admin ───────────────────────────────────────────────────────────────

  it('maps "not admin" to NOT_ADMIN', () => {
    const result = mapSorobanError('caller is not admin');
    expect(result.code).toBe(SorobanErrorCode.NOT_ADMIN);
  });

  it('maps "invalid admin" to INVALID_ADMIN', () => {
    const result = mapSorobanError('invalid admin address');
    expect(result.code).toBe(SorobanErrorCode.INVALID_ADMIN);
  });

  // ── Input / params ──────────────────────────────────────────────────────

  it('maps Value.InvalidInput HostError to INVALID_INPUT', () => {
    const result = mapSorobanError('HostError: Error(Value, InvalidInput)');
    expect(result.code).toBe(SorobanErrorCode.INVALID_INPUT);
  });

  it('maps WasmVm.InvalidAction HostError to INVALID_INPUT', () => {
    const result = mapSorobanError('HostError: Error(WasmVm, InvalidAction)');
    expect(result.code).toBe(SorobanErrorCode.INVALID_INPUT);
  });

  it('maps "account does not exist" to NOT_FOUND', () => {
    const result = mapSorobanError('account does not exist on the network');
    expect(result.code).toBe(SorobanErrorCode.NOT_FOUND);
  });

  it('maps "contract does not exist" to NOT_FOUND', () => {
    const result = mapSorobanError('contract does not exist');
    expect(result.code).toBe(SorobanErrorCode.NOT_FOUND);
  });

  // ── Resource limits ─────────────────────────────────────────────────────

  it('maps Budget.ExceededLimit HostError to BUDGET_EXCEEDED', () => {
    const result = mapSorobanError('HostError: Error(Budget, ExceededLimit)');
    expect(result.code).toBe(SorobanErrorCode.BUDGET_EXCEEDED);
  });

  it('maps "transaction too large" to BUDGET_EXCEEDED', () => {
    const result = mapSorobanError('transaction too large');
    expect(result.code).toBe(SorobanErrorCode.BUDGET_EXCEEDED);
  });

  // ── Unknown / generic ───────────────────────────────────────────────────

  it('returns UNKNOWN for unrecognised errors', () => {
    const result = mapSorobanError('some completely unknown contract error xyz');
    expect(result.code).toBe(SorobanErrorCode.UNKNOWN);
    expect(result.message).toBeTruthy();
  });

  it('extracts HostError type and code for unknown structured errors', () => {
    const result = mapSorobanError('HostError: Error(Foo, BarBaz)');
    expect(result.code).toBe(SorobanErrorCode.UNKNOWN);
    expect(result.details).toEqual({ errorType: 'Foo', errorCode: 'BarBaz' });
  });

  it('always includes technicalError in the result', () => {
    const raw = 'some raw error string';
    const result = mapSorobanError(raw);
    expect(result.technicalError).toBe(raw);
  });

  it('always returns a non-empty message', () => {
    const result = mapSorobanError('');
    expect(result.message.length).toBeGreaterThan(0);
  });

  // ── Error code stability (public API pin) ───────────────────────────────
  // Error codes are part of the public API. These numeric pins guard against
  // accidental renumbering when the enum is refactored to free variant space.

  it('pins overloaded error codes to their current numeric values', () => {
    expect(SorobanErrorCode.CONTRACT_PAUSED).toBe(3);
    expect(SorobanErrorCode.OVERPAYMENT).toBe(17);
    expect(SorobanErrorCode.ALREADY_SPENT).toBe(21);
    expect(SorobanErrorCode.INVALID_DISPUTE_STATE).toBe(34);
  });
});
