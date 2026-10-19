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
        isSimulationError: jest.fn((sim: any) => Boolean(sim && 'error' in sim)),
        isSimulationRestore: jest.fn((sim: any) => Boolean(sim && 'restorePreamble' in sim)),
      },
    },
  };
});

import { BadRequestException } from '@nestjs/common';
import { SorobanErrorCode } from '../common/soroban-errors';
import { SorobanRpcService } from './soroban-rpc.service';
import { TransactionsService } from './transaction.service';

describe('TransactionsService', () => {
  let service: TransactionsService;
  let mockSorobanRpcService: jest.Mocked<Partial<SorobanRpcService>>;

  const mockSuccessfulSimulation = {
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
  };

  beforeEach(() => {
    mockSorobanRpcService = {
      getNetworkPassphrase: jest.fn().mockResolvedValue('Test SDF Network ; September 2015'),
      getAccount: jest.fn().mockResolvedValue({ accountId: 'G123', sequence: '1' } as any),
      simulateTransaction: jest.fn().mockResolvedValue(mockSuccessfulSimulation as any),
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

  describe('simulateOperation', () => {
    const testDto = {
      contractId: 'CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      method: 'transfer',
      params: [],
      sourceAccount: 'GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB',
    };

    it('builds and simulates a real transaction via SorobanRpcService', async () => {
      const result = await service.simulateOperation(testDto);

      expect(mockSorobanRpcService.getAccount).toHaveBeenCalledWith(testDto.sourceAccount);
      expect(mockSorobanRpcService.simulateTransaction).toHaveBeenCalledTimes(1);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.details).toEqual({
          cpuInstructions: 123,
          memoryBytes: 0,
          ledgerReads: 3,
          ledgerWrites: 1,
          eventBytes: 77,
          returnValueBytes: 'retval-xdr'.length,
          minResourceFee: '250',
        });
      }
    });

    it('derives error response from SorobanRpc.Api.isSimulationError result via mapSorobanError', async () => {
      (mockSorobanRpcService.simulateTransaction as jest.Mock).mockResolvedValueOnce({
        error: 'HostError: Error(Auth, NotAuthorized)',
      });

      const result = await service.simulateOperation(testDto);

      expect(result.success).toBe(false);
      expect(result.error).toBe(SorobanErrorCode.UNAUTHORIZED);
      expect(result.userMessage).toBe('You are not authorised to perform this operation.');
    });

    it('demonstrates two different real contract states produce two different simulation outcomes', async () => {
      // Contract State 1: Active state where operation succeeds
      (mockSorobanRpcService.simulateTransaction as jest.Mock).mockResolvedValueOnce(
        mockSuccessfulSimulation,
      );

      const state1Outcome = await service.simulateOperation(testDto);

      // Contract State 2: Contract is paused on-chain
      (mockSorobanRpcService.simulateTransaction as jest.Mock).mockResolvedValueOnce({
        error: 'HostError: Error(Contract, #1) - contract is currently paused',
      });

      const state2Outcome = await service.simulateOperation(testDto);

      // Different contract states produced different simulation outcomes for identical input
      expect(state1Outcome.success).toBe(true);
      expect(state1Outcome.details?.cpuInstructions).toBe(123);

      expect(state2Outcome.success).toBe(false);
      expect(state2Outcome.error).toBe(SorobanErrorCode.CONTRACT_PAUSED);
      expect(state2Outcome.userMessage).toBe(
        'The contract is currently paused. Please try again later.',
      );

      expect(state1Outcome.success).not.toEqual(state2Outcome.success);
    });

    it('handles simulation restore required state', async () => {
      (mockSorobanRpcService.simulateTransaction as jest.Mock).mockResolvedValueOnce({
        restorePreamble: {
          transactionData: 'restore-tx-data',
          minResourceFee: '100',
        },
      });

      const result = await service.simulateOperation(testDto);

      expect(result.success).toBe(false);
      expect(result.error).toBe(SorobanErrorCode.RESTORE_REQUIRED);
      expect(result.details?.restorePreamble).toBeDefined();
    });

    it('handles missing source account gracefully', async () => {
      (mockSorobanRpcService.getAccount as jest.Mock).mockRejectedValueOnce(
        new Error('account does not exist on the network'),
      );

      const result = await service.simulateOperation(testDto);

      expect(result.success).toBe(false);
      expect(result.error).toContain('account does not exist');
      expect(result.userMessage).toContain('Source account not found');
    });
  });
});
