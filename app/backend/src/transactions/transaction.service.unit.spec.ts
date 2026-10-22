jest.mock('@stellar/stellar-sdk', () => {
  class MockAccount {
    accountId: string;
    sequence: string;

    constructor(accountId: string, sequence: string) {
      this.accountId = accountId;
      this.sequence = sequence;
    }
  }

  class MockContract {
    contractId: string;

    constructor(contractId: string) {
      this.contractId = contractId;
    }

    call(method: string, ...params: unknown[]) {
      return { contractId: this.contractId, method, params };
    }
  }

  class MockTransactionBuilder {
    account: MockAccount;
    options: { fee: string; networkPassphrase: string };
    operations: unknown[] = [];

    constructor(account: MockAccount, options: { fee: string; networkPassphrase: string }) {
      this.account = account;
      this.options = options;
    }

    addOperation(operation: unknown) {
      this.operations.push(operation);
      return this;
    }

    setTimeout() {
      return this;
    }

    build() {
      const payload = JSON.stringify({
        accountId: this.account.accountId,
        sequence: this.account.sequence,
        fee: this.options.fee,
        networkPassphrase: this.options.networkPassphrase,
        operations: this.operations,
      });
      return {
        payload,
        toEnvelope: () => ({ toXDR: () => Buffer.from(payload).toString('base64') }),
      };
    }
  }

  const assembleTransaction = jest.fn((tx: { payload: string }) => ({
    build: () => ({
      toEnvelope: () => ({ toXDR: () => Buffer.from(`${tx.payload}:assembled`).toString('base64') }),
    }),
  }));

  const MockTransactionFromXDR = jest.fn((xdr: string, passphrase: string) => {
    const decoded = Buffer.from(xdr, 'base64').toString('utf8');
    return {
      xdr: decoded,
      passphrase,
      toEnvelope: () => ({ toXDR: () => xdr }),
      toXDR: () => xdr,
    };
  });

  return {
    Account: MockAccount,
    Contract: MockContract,
    TransactionBuilder: MockTransactionBuilder,
    Transaction: {
      fromXDR: MockTransactionFromXDR,
    },
    TimeoutInfinite: 0,
    rpc: {
      assembleTransaction,
      Api: {
        isSimulationError: jest.fn(() => false),
        isSimulationRestore: jest.fn(() => false),
      },
    },
  };
});

import { BadRequestException } from '@nestjs/common';

import { SorobanErrorCode, SorobanRpcService } from './soroban-rpc.service';
import { TransactionsService } from './transaction.service';

describe('TransactionsService', () => {
  let service: TransactionsService;
  let mockSorobanRpcService: jest.Mocked<Partial<SorobanRpcService>>;

  const signedXDR = Buffer.from('signed-transaction-envelope').toString('base64');

  beforeEach(() => {
    mockSorobanRpcService = {
      getNetworkPassphrase: jest.fn().mockResolved('Test DF Network ; September 2015'),
      getAccount: jest.fn().mockResolved({ accountId: 'G123', sequence: '1' }),
      simulateTransaction: jest.fn().mockResolved({
        transactionData: {
          build: () => ({
            resources: () => ({
              instructions: () => 123,
              footprint: () => ({
                readOnly: () => [1, 2],
                readWrite: () => [3],
              }),
              writeBytes: () => 77,
            }),
          }),
        },
        minResourceFee: '250',
        result: {
          retval: {
            toXDR: () => 'retval-xdr',
          },
        },
      }),
      submitTransaction: jest.fn().mockResolved({
        hash: 'network-assigned-hash',
        status: 'PENDING',
        latestLedger: 1234,
      }),
    };

    service = new TransactionsService(mockSorobanRpcService as unknown as SorobanRpcService);
  });

  it('returns a simulation summary and idempotency key', async () => {
    const result = await service.composeTransaction({
      contractId: 'C123',
      method: 'health_check',
      params: [],
      sourceAccount: 'G123',
    });

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.idempotencyKey).toBeDefined();
      expect(result.simulationSummary.footprint.readOnly).toBe(2);
      expect(result.feeEstimate.totalFee).toBe('350');
    }
  });

  it('reuses the cached response for the same idempotency key', async () => {
    const payload = {
      contractId: 'C123',
      method: 'health_check',
      params: [],
      sourceAccount: 'G123',
      idempotencyKey: 'same-key',
    };

    const first = await service.composeTransaction(payload);
    const second = await service.composeTransaction(payload);

    expect(second).toEqual(first);
    expect(mockSorobanRpcService.simulateTransaction).toHaveBeenCalledTimes(1);
  });

  it('rejects reusing an idempotency key with a different payload', async () => {
    await service.composeTransaction({
      contractId: 'C123',
      method: 'health_check',
      params: [],
      sourceAccount: 'G123',
      idempotencyKey: 'same-key',
    });

    await expect(
      service.composeTransaction({
        contractId: 'C123',
        method: 'different_method',
        params: [],
        sourceAccount: 'G123',
        idempotencyKey: 'same-key',
      }),
    ).rejects.toThrow(BadRequestException);
  });

  it('broadcasts the signed transaction through SorobanRpcService and returns the network-hash', async () => {
    const result = await service.submitSignedXHR(signedXDR);

    expect(mockSorobanRpcService.submitTransaction).toHaveBeenCalledTimes(1);
    expect(mockSorobanRpcService.submitTransaction).toHaveBeenCalledWith(
      expect.objectContaining({ toXDR: expect.any(String) }),
    );
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.hash).toBe('network-assigned-hash');
      expect(result.status).toBe('PENDING');
      expect(result.latestLedger).toBe(1234);
    }
  });

  it('caches the real submission result for the same idempotency key', async () => {
    const first = await service.submitSignedXHR(signedXHR, 'id-1');
    const second = await service.submitSignedXHR(signedXHR, 'id-1');

    expect(second).toEqual(first);
    expect(mockSorobanRpcService.submitTransaction).toHaveBeenCalledTimes(1);
  });

  it('maps real submission errors to the SorobanErrorCode catalog', async () => {
    (mockSorobanRpcService.submitTransaction as jest.Mock).mockRejected(
      new Error('tx_bad_seq: transaction sequence is out of order'),
    );

    const result = await service.submitSignedXHR(signedXHR);

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.errorCode).toBe(SorobanErrorCode.TX_BAD_SEQ);
    }
  });

  it('returns an invalid-xdr error without broadcasting malformed input', async () => {
    const result = await service.submitSignedXHR('');

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.errorCode).toBe(SorobanErrorCode.INVALID_XDR);
    }
    expect(mockSorobanRpcService.submitTransaction).not.toHaveBeenCalled();
  });
});
