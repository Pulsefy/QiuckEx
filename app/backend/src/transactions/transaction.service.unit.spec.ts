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

  return {
    Account: MockAccount,
    Contract: MockContract,
    TransactionBuilder: MockTransactionBuilder,
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

import { SorobanRpcService } from './soroban-rpc.service';
import { TransactionsService } from './transaction.service';

describe('TransactionsService', () => {
  let service: TransactionsService;
  let mockSorobanRpcService: jest.Mocked<Partial<SorobanRpcService>>;

  beforeEach(() => {
    mockSorobanRpcService = {
      getNetworkPassphrase: jest.fn().mockResolvedValue('Test SDF Network ; September 2015'),
      getAccount: jest.fn().mockResolvedValue({ accountId: 'G123', sequence: '1' }),
      simulateTransaction: jest.fn().mockResolvedValue({
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
});
