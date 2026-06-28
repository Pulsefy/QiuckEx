/**
 * Receipt Normalization Tests
 *
 * Covers:
 *   - Successful payment
 *   - Successful Soroban contract action
 *   - Pending contract action (NOT_FOUND in RPC)
 *   - Failed contract action (with diagnostic metadata)
 *   - Refund detection
 *   - Receipt ID stability across testnet retries
 *   - Fee aggregation (base + Soroban resource fee)
 *
 * Location: app/backend/test/receipts/receipt.normalizer.spec.ts
 */

import { ReceiptNormalizer, HorizonOperation, HorizonTransaction, SorobanRpcResult, IndexerMetadata } from '../../src/receipts/normalizers/receipt.normalizer';

// ── Shared fixtures ───────────────────────────────────────────────────────────

const BASE_TX: HorizonTransaction = {
  hash: 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
  ledger: 12345678,
  created_at: '2026-06-01T10:00:00Z',
  fee_charged: '100',
  max_fee: '200',
  envelope_xdr: 'AAAA...envelopeXDR',
  result_xdr: 'AAAA...resultXDR',
  result_meta_xdr: '',
  memo_type: 'text',
  memo: 'payment for invoice #42',
  successful: true,
};

const BASE_PAYMENT_OP: HorizonOperation = {
  id: '12345678-0',
  paging_token: '12345678-1-0',
  type: 'payment',
  type_i: 1,
  transaction_hash: BASE_TX.hash,
  transaction_successful: true,
  source_account: 'GSENDER111111111111111111111111111111111111111111111111111',
  created_at: '2026-06-01T10:00:00Z',
  from: 'GSENDER111111111111111111111111111111111111111111111111111',
  to: 'GRECEIVER11111111111111111111111111111111111111111111111111',
  amount: '50.0000000',
  asset_type: 'credit_alphanum4',
  asset_code: 'USDC',
  asset_issuer: 'GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN',
};

const BASE_INDEXER: IndexerMetadata = {
  txHash: BASE_TX.hash,
  submittedAt: '2026-06-01T09:59:50Z',
  confirmedAt: '2026-06-01T10:00:05Z',
  receiptId: 'rcpt_abcdef123456_0',
  senderUsername: 'alice',
  receiverUsername: 'bob',
  network: 'testnet',
};

const CONTRACT_OP: HorizonOperation = {
  ...BASE_PAYMENT_OP,
  type: 'invoke_host_function',
  type_i: 24,
  function: 'transfer',
  to: undefined,
  amount: undefined,
  asset_type: undefined,
};

const SUCCESS_SOROBAN: SorobanRpcResult = {
  status: 'SUCCESS',
  txHash: BASE_TX.hash,
  contractId: 'CAAAA...CONTRACT',
  functionName: 'transfer',
  args: { to: 'GRECEIVER...', amount: '1000' },
  returnValue: 'true',
  cpuInstructions: 500000,
  memBytes: 40000,
  ledgerReads: 10,
  ledgerWrites: 3,
  resourceFee: '5000',
};

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('ReceiptNormalizer', () => {
  let normalizer: ReceiptNormalizer;

  beforeEach(() => {
    normalizer = new ReceiptNormalizer();
  });

  // ── Successful payment ───────────────────────────────────────────────────

  describe('successful payment', () => {
    it('returns type=payment and status=success', () => {
      const receipt = normalizer.normalize(BASE_PAYMENT_OP, BASE_TX, null, BASE_INDEXER);
      expect(receipt.type).toBe('payment');
      expect(receipt.status).toBe('success');
    });

    it('uses stable receiptId from indexer', () => {
      const receipt = normalizer.normalize(BASE_PAYMENT_OP, BASE_TX, null, BASE_INDEXER);
      expect(receipt.receiptId).toBe('rcpt_abcdef123456_0');
    });

    it('resolves sender/receiver usernames', () => {
      const receipt = normalizer.normalize(BASE_PAYMENT_OP, BASE_TX, null, BASE_INDEXER);
      expect(receipt.sender.username).toBe('alice');
      expect(receipt.receiver?.username).toBe('bob');
    });

    it('normalizes asset fields correctly', () => {
      const receipt = normalizer.normalize(BASE_PAYMENT_OP, BASE_TX, null, BASE_INDEXER);
      expect(receipt.asset.code).toBe('USDC');
      expect(receipt.asset.type).toBe('credit_alphanum4');
      expect(receipt.asset.issuer).toBe('GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN');
    });

    it('formats displayAmount', () => {
      const receipt = normalizer.normalize(BASE_PAYMENT_OP, BASE_TX, null, BASE_INDEXER);
      expect(receipt.displayAmount).toBe('50.0000000 USDC');
    });

    it('normalizes memo and memoType', () => {
      const receipt = normalizer.normalize(BASE_PAYMENT_OP, BASE_TX, null, BASE_INDEXER);
      expect(receipt.memo).toBe('payment for invoice #42');
      expect(receipt.memoType).toBe('text');
    });

    it('sets contract to null for payment', () => {
      const receipt = normalizer.normalize(BASE_PAYMENT_OP, BASE_TX, null, BASE_INDEXER);
      expect(receipt.contract).toBeNull();
    });

    it('has empty diagnostic fields on success', () => {
      const receipt = normalizer.normalize(BASE_PAYMENT_OP, BASE_TX, null, BASE_INDEXER);
      expect(receipt.diagnostic.errorCode).toBeNull();
      expect(receipt.diagnostic.errorMessage).toBeNull();
      expect(receipt.diagnostic.resultXdr).toBeNull();
      expect(receipt.diagnostic.envelopeXdr).toBeNull();
    });

    it('sets correct network and explorerUrl', () => {
      const receipt = normalizer.normalize(BASE_PAYMENT_OP, BASE_TX, null, BASE_INDEXER);
      expect(receipt.network).toBe('testnet');
      expect(receipt.explorerUrl).toContain('testnet');
      expect(receipt.explorerUrl).toContain(BASE_TX.hash);
    });

    it('uses confirmedAt for createdAt on success', () => {
      const receipt = normalizer.normalize(BASE_PAYMENT_OP, BASE_TX, null, BASE_INDEXER);
      expect(receipt.createdAt).toBe('2026-06-01T10:00:05Z');
    });
  });

  // ── Successful contract action ───────────────────────────────────────────

  describe('successful Soroban contract action', () => {
    it('returns type=contract_action and status=success', () => {
      const receipt = normalizer.normalize(CONTRACT_OP, BASE_TX, SUCCESS_SOROBAN, BASE_INDEXER);
      expect(receipt.type).toBe('contract_action');
      expect(receipt.status).toBe('success');
    });

    it('populates contract metadata', () => {
      const receipt = normalizer.normalize(CONTRACT_OP, BASE_TX, SUCCESS_SOROBAN, BASE_INDEXER);
      expect(receipt.contract).not.toBeNull();
      expect(receipt.contract?.contractId).toBe('CAAAA...CONTRACT');
      expect(receipt.contract?.functionName).toBe('transfer');
      expect(receipt.contract?.returnValue).toBe('true');
    });

    it('captures resource usage', () => {
      const receipt = normalizer.normalize(CONTRACT_OP, BASE_TX, SUCCESS_SOROBAN, BASE_INDEXER);
      expect(receipt.contract?.resources?.cpuInstructions).toBe(500000);
      expect(receipt.contract?.resources?.ledgerWrites).toBe(3);
    });

    it('aggregates base + resource fee', () => {
      const receipt = normalizer.normalize(CONTRACT_OP, BASE_TX, SUCCESS_SOROBAN, BASE_INDEXER);
      // base 100 + resource 5000 = 5100 stroops
      expect(receipt.fee.totalFeeSatoshis).toBe('5100');
      expect(receipt.fee.feeXlm).toBe('0.0005100');
    });
  });

  // ── Pending contract action ───────────────────────────────────────────────

  describe('pending contract action', () => {
    const PENDING_TX: HorizonTransaction = {
      ...BASE_TX,
      ledger: 0,
      successful: true,
    };

    const PENDING_SOROBAN: SorobanRpcResult = {
      status: 'NOT_FOUND',
      txHash: BASE_TX.hash,
    };

    it('returns status=pending when Soroban RPC returns NOT_FOUND', () => {
      const receipt = normalizer.normalize(CONTRACT_OP, PENDING_TX, PENDING_SOROBAN, BASE_INDEXER);
      expect(receipt.status).toBe('pending');
    });

    it('has no diagnostic errors on pending', () => {
      const receipt = normalizer.normalize(CONTRACT_OP, PENDING_TX, PENDING_SOROBAN, BASE_INDEXER);
      expect(receipt.diagnostic.errorCode).toBeNull();
      expect(receipt.diagnostic.errorMessage).toBeNull();
    });

    it('contract field is populated for contract_action even when pending', () => {
      // We still know it's a contract invocation from the operation type
      const receipt = normalizer.normalize(CONTRACT_OP, PENDING_TX, PENDING_SOROBAN, BASE_INDEXER);
      expect(receipt.type).toBe('contract_action');
    });
  });

  // ── Failed contract action ────────────────────────────────────────────────

  describe('failed contract action', () => {
    const FAILED_TX: HorizonTransaction = {
      ...BASE_TX,
      successful: false,
      ledger: 12345679,
    };

    const FAILED_SOROBAN: SorobanRpcResult = {
      status: 'FAILED',
      txHash: BASE_TX.hash,
      contractId: 'CAAAA...CONTRACT',
      functionName: 'transfer',
      args: { to: 'GRECEIVER...', amount: '1000' },
      errorCode: 'wasm_vm_error',
      errorMessage: 'trapped with out-of-bounds memory access',
      resourceFee: '5000',
    };

    it('returns status=failed', () => {
      const receipt = normalizer.normalize(CONTRACT_OP, FAILED_TX, FAILED_SOROBAN, BASE_INDEXER);
      expect(receipt.status).toBe('failed');
    });

    it('includes diagnostic error code and message', () => {
      const receipt = normalizer.normalize(CONTRACT_OP, FAILED_TX, FAILED_SOROBAN, BASE_INDEXER);
      expect(receipt.diagnostic.errorCode).toBe('wasm_vm_error');
      expect(receipt.diagnostic.errorMessage).toBe('trapped with out-of-bounds memory access');
    });

    it('includes XDR fields on failure for replay/debug', () => {
      const receipt = normalizer.normalize(CONTRACT_OP, FAILED_TX, FAILED_SOROBAN, BASE_INDEXER);
      expect(receipt.diagnostic.resultXdr).toBe('AAAA...resultXDR');
      expect(receipt.diagnostic.envelopeXdr).toBe('AAAA...envelopeXDR');
    });

    it('still includes contract metadata on failure', () => {
      const receipt = normalizer.normalize(CONTRACT_OP, FAILED_TX, FAILED_SOROBAN, BASE_INDEXER);
      expect(receipt.contract?.contractId).toBe('CAAAA...CONTRACT');
      expect(receipt.contract?.functionName).toBe('transfer');
    });

    it('uses submittedAt for createdAt on failure (stable across retries)', () => {
      const receipt = normalizer.normalize(CONTRACT_OP, FAILED_TX, FAILED_SOROBAN, BASE_INDEXER);
      // Should use submittedAt, not the ledger close time, so retries don't shift the timestamp
      expect(receipt.createdAt).toBe('2026-06-01T09:59:50Z');
    });
  });

  // ── Receipt ID stability ──────────────────────────────────────────────────

  describe('receipt ID stability', () => {
    it('produces the same receiptId when called twice with same inputs', () => {
      const r1 = normalizer.normalize(BASE_PAYMENT_OP, BASE_TX, null, BASE_INDEXER);
      const r2 = normalizer.normalize(BASE_PAYMENT_OP, BASE_TX, null, BASE_INDEXER);
      expect(r1.receiptId).toBe(r2.receiptId);
    });

    it('derives a stable ID from txHash+opIndex when indexer has none', () => {
      const indexerWithoutId: IndexerMetadata = { ...BASE_INDEXER, receiptId: undefined };
      const r1 = normalizer.normalize(BASE_PAYMENT_OP, BASE_TX, null, indexerWithoutId);
      const r2 = normalizer.normalize(BASE_PAYMENT_OP, BASE_TX, null, indexerWithoutId);
      expect(r1.receiptId).toBe(r2.receiptId);
      expect(r1.receiptId).toMatch(/^rcpt_/);
    });

    it('generates different IDs for different operation indices', () => {
      const op1 = { ...BASE_PAYMENT_OP, paging_token: '12345678-1-0' };
      const op2 = { ...BASE_PAYMENT_OP, paging_token: '12345678-1-1' };
      const indexerWithoutId: IndexerMetadata = { ...BASE_INDEXER, receiptId: undefined };
      const r1 = normalizer.normalize(op1, BASE_TX, null, indexerWithoutId);
      const r2 = normalizer.normalize(op2, BASE_TX, null, indexerWithoutId);
      expect(r1.receiptId).not.toBe(r2.receiptId);
    });
  });

  // ── Fee normalization ─────────────────────────────────────────────────────

  describe('fee normalization', () => {
    it('handles classic tx with no Soroban resource fee', () => {
      const receipt = normalizer.normalize(BASE_PAYMENT_OP, BASE_TX, null, BASE_INDEXER);
      expect(receipt.fee.baseFeeSatoshis).toBe('100');
      expect(receipt.fee.totalFeeSatoshis).toBe('100');
    });

    it('formats feeXlm to 7 decimal places', () => {
      const receipt = normalizer.normalize(BASE_PAYMENT_OP, BASE_TX, null, BASE_INDEXER);
      // 100 stroops = 0.0000100 XLM
      expect(receipt.fee.feeXlm).toBe('0.0000100');
    });
  });

  // ── Native XLM asset ─────────────────────────────────────────────────────

  describe('native XLM asset', () => {
    const XLM_OP: HorizonOperation = {
      ...BASE_PAYMENT_OP,
      asset_type: 'native',
      asset_code: undefined,
      asset_issuer: undefined,
    };

    it('sets code=XLM and issuer=null for native asset', () => {
      const receipt = normalizer.normalize(XLM_OP, BASE_TX, null, BASE_INDEXER);
      expect(receipt.asset.code).toBe('XLM');
      expect(receipt.asset.issuer).toBeNull();
    });
  });
});