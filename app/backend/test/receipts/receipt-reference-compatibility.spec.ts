/**
 * Receipt Reference Compatibility Tests — SC-W7-07
 *
 * Tests that validate backend receipt normalization is compatible with
 * the new receipt reference fields emitted from contract events.
 *
 * Location: app/backend/test/receipts/receipt-reference-compatibility.spec.ts
 */

import { ReceiptNormalizer, SorobanRpcResult, HorizonOperation, HorizonTransaction, IndexerMetadata } from '../../src/receipts/normalizers/receipt.normalizer';
import { NormalizedReceipt } from '../../src/receipts/schemas/receipt.schema';

describe('Receipt Reference Compatibility (SC-W7-07)', () => {
  let normalizer: ReceiptNormalizer;

  beforeEach(() => {
    normalizer = new ReceiptNormalizer({} as any);
  });

  // ---------------------------------------------------------------------------
  // Mock data helpers
  // ---------------------------------------------------------------------------

  const createMockOperation = (overrides: Partial<HorizonOperation> = {}): HorizonOperation => ({
    id: '123456789',
    paging_token: '123456789-1-0',
    type: 'invoke_host_function',
    type_i: 12,
    transaction_hash: 'abc123def456',
    transaction_successful: true,
    source_account: 'GABCD1234EFGH5678IJKL9012MNOP3456QRST7890',
    created_at: '2023-01-01T00:00:00Z',
    function: 'deposit',
    ...overrides,
  });

  const createMockTransaction = (overrides: Partial<HorizonTransaction> = {}): HorizonTransaction => ({
    hash: 'abc123def456',
    ledger: 12345,
    created_at: '2023-01-01T00:00:00Z',
    fee_charged: '100',
    max_fee: '100',
    envelope_xdr: 'AAA=',
    result_xdr: 'AAA=',
    result_meta_xdr: 'AAA=',
    memo_type: 'none',
    successful: true,
    ...overrides,
  });

  const createMockSorobanResult = (overrides: Partial<SorobanRpcResult> = {}): SorobanRpcResult => ({
    status: 'SUCCESS',
    txHash: 'abc123def456',
    contractId: 'CABCD1234EFGH5678IJKL9012MNOP3456QRST7890',
    functionName: 'deposit',
    args: {},
    returnValue: 'success',
    cpuInstructions: 1000,
    memBytes: 2000,
    ledgerReads: 10,
    ledgerWrites: 5,
    ...overrides,
  });

  const createMockIndexerMetadata = (overrides: Partial<IndexerMetadata> = {}): IndexerMetadata => ({
    txHash: 'abc123def456',
    submittedAt: '2023-01-01T00:00:00Z',
    confirmedAt: '2023-01-01T00:00:10Z',
    network: 'testnet',
    ...overrides,
  });

  // ---------------------------------------------------------------------------
  // Schema compatibility tests
  // ---------------------------------------------------------------------------

  test('should handle receipt reference in Soroban RPC result', () => {
    const operation = createMockOperation();
    const transaction = createMockTransaction();
    const soroban = createMockSorobanResult({
      receiptReference: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2',
    });
    const indexer = createMockIndexerMetadata();

    const receipt = normalizer.normalize(operation, transaction, soroban, indexer);

    expect(receipt).toBeDefined();
    expect(receipt.contract).toBeDefined();
    expect(receipt.contract?.receiptReference).toBe('a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2');
  });

  test('should handle missing receipt reference gracefully', () => {
    const operation = createMockOperation();
    const transaction = createMockTransaction();
    const soroban = createMockSorobanResult(); // No receiptReference
    const indexer = createMockIndexerMetadata();

    const receipt = normalizer.normalize(operation, transaction, soroban, indexer);

    expect(receipt).toBeDefined();
    expect(receipt.contract).toBeDefined();
    expect(receipt.contract?.receiptReference).toBeUndefined();
  });

  test('should handle null contract data without receipt reference', () => {
    const operation = createMockOperation({ type: 'payment' }); // Not a contract action
    const transaction = createMockTransaction();
    const soroban = null; // No Soroban data
    const indexer = createMockIndexerMetadata();

    const receipt = normalizer.normalize(operation, transaction, soroban, indexer);

    expect(receipt).toBeDefined();
    expect(receipt.contract).toBeNull();
  });

  // ---------------------------------------------------------------------------
  // Determinism tests
  // ---------------------------------------------------------------------------

  test('should produce deterministic receipt hash with receipt reference', () => {
    const operation = createMockOperation();
    const transaction = createMockTransaction();
    const soroban = createMockSorobanResult({
      receiptReference: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2',
    });
    const indexer = createMockIndexerMetadata();

    const receipt1 = normalizer.normalize(operation, transaction, soroban, indexer);
    const receipt2 = normalizer.normalize(operation, transaction, soroban, indexer);

    expect(receipt1.receiptHash).toBe(receipt2.receiptHash);
    expect(receipt1.receiptId).toBe(receipt2.receiptId);
  });

  test('should handle different receipt references producing different receipts', () => {
    const operation = createMockOperation();
    const transaction = createMockTransaction();
    const soroban1 = createMockSorobanResult({
      receiptReference: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2',
    });
    const soroban2 = createMockSorobanResult({
      receiptReference: 'f1e2d3c4b5a6f1e2d3c4b5a6f1e2d3c4b5a6f1e2d3c4b5a6f1e2d3c4b5a6f1e2',
    });
    const indexer = createMockIndexerMetadata();

    const receipt1 = normalizer.normalize(operation, transaction, soroban1, indexer);
    const receipt2 = normalizer.normalize(operation, transaction, soroban2, indexer);

    // Receipt IDs should be the same (based on tx hash and operation index)
    expect(receipt1.receiptId).toBe(receipt2.receiptId);
    
    // But contract metadata should differ
    expect(receipt1.contract?.receiptReference).not.toBe(receipt2.contract?.receiptReference);
  });

  // ---------------------------------------------------------------------------
  // Backward compatibility tests
  // ---------------------------------------------------------------------------

  test('should handle legacy events without receipt reference', () => {
    const operation = createMockOperation();
    const transaction = createMockTransaction();
    const soroban = createMockSorobanResult({
      // Simulate legacy event without receiptReference
      receiptReference: undefined,
    });
    const indexer = createMockIndexerMetadata();

    const receipt = normalizer.normalize(operation, transaction, soroban, indexer);

    expect(receipt).toBeDefined();
    expect(receipt.contract).toBeDefined();
    expect(receipt.contract?.receiptReference).toBeUndefined();
    
    // Should still produce valid receipt hash
    expect(receipt.receiptHash).toBeDefined();
    expect(receipt.receiptHash).toMatch(/^rch_[a-f0-9]{64}$/);
  });

  test('should handle various receipt reference formats', () => {
    const operation = createMockOperation();
    const transaction = createMockTransaction();
    const indexer = createMockIndexerMetadata();

    // Test different valid receipt reference formats
    const receiptReferences = [
      'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2',
      '0000000000000000000000000000000000000000000000000000000000000000',
      'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
    ];

    receiptReferences.forEach((ref) => {
      const soroban = createMockSorobanResult({ receiptReference: ref });
      const receipt = normalizer.normalize(operation, transaction, soroban, indexer);
      
      expect(receipt).toBeDefined();
      expect(receipt.contract?.receiptReference).toBe(ref);
    });
  });

  // ---------------------------------------------------------------------------
  // Schema validation tests
  // ---------------------------------------------------------------------------

  test('should produce valid NormalizedReceipt schema with receipt reference', () => {
    const operation = createMockOperation();
    const transaction = createMockTransaction();
    const soroban = createMockSorobanResult({
      receiptReference: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2',
    });
    const indexer = createMockIndexerMetadata();

    const receipt = normalizer.normalize(operation, transaction, soroban, indexer);

    // Validate all required fields are present
    expect(receipt.receiptId).toBeDefined();
    expect(receipt.receiptHash).toBeDefined();
    expect(receipt.txHash).toBeDefined();
    expect(receipt.operationIndex).toBeDefined();
    expect(receipt.type).toBeDefined();
    expect(receipt.status).toBeDefined();
    expect(receipt.createdAt).toBeDefined();
    expect(receipt.updatedAt).toBeDefined();
    expect(receipt.sender).toBeDefined();
    expect(receipt.asset).toBeDefined();
    expect(receipt.amount).toBeDefined();
    expect(receipt.fee).toBeDefined();
    expect(receipt.diagnostic).toBeDefined();
    expect(receipt.network).toBeDefined();
    expect(receipt.explorerUrl).toBeDefined();

    // Validate contract-specific fields
    expect(receipt.contract).toBeDefined();
    expect(receipt.contract?.contractId).toBeDefined();
    expect(receipt.contract?.functionName).toBeDefined();
    expect(receipt.contract?.receiptReference).toBeDefined();
  });

  test('should maintain backward compatibility for non-contract actions', () => {
    const operation = createMockOperation({ 
      type: 'payment',
      function: undefined,
    });
    const transaction = createMockTransaction();
    const soroban = null;
    const indexer = createMockIndexerMetadata();

    const receipt = normalizer.normalize(operation, transaction, soroban, indexer);

    expect(receipt).toBeDefined();
    expect(receipt.type).toBe('payment');
    expect(receipt.contract).toBeNull();
  });
});
