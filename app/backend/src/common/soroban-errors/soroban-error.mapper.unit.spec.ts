import { mapSorobanError } from './soroban-error.mapper';
import { SorobanErrorCode } from './soroban-error.codes';

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
});
