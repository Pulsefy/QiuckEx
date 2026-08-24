import { BadRequestException, NotFoundException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as StellarSdk from '@stellar/stellar-sdk';

import { ContractViewsService } from './contract-views.service';

// A well-formed (all-zero) contract address so `new StellarSdk.Contract(id)` parses.
const CONTRACT_ID = StellarSdk.StrKey.encodeContract(Buffer.alloc(32));
const VALID_TOKEN = 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF';

describe('ContractViewsService', () => {
  let service: ContractViewsService;
  let configGet: jest.Mock;
  let simulateTransaction: jest.Mock;
  let rpcServer: { simulateTransaction: jest.Mock };

  const stellarConfig = {
    network: 'testnet',
    networkPassphrase: StellarSdk.Networks.TESTNET,
    sorobanRpcUrl: 'https://soroban-testnet.stellar.org',
  };

  beforeEach(() => {
    configGet = jest.fn((key: string) => {
      if (key === 'stellar') return stellarConfig;
      if (key === 'QUICKEX_CONTRACT_ID') return CONTRACT_ID;
      return undefined;
    });

    simulateTransaction = jest.fn();
    rpcServer = { simulateTransaction };

    service = new ContractViewsService({
      get: configGet,
    } as unknown as ConfigService);
    // Inject a fake RPC server so no real network call happens.
    (service as unknown as { rpc: unknown }).rpc = rpcServer as never;
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('returns the accrued fee balance for a token as a decimal string', async () => {
    simulateTransaction.mockResolvedValue({
      result: {
        retval: StellarSdk.nativeToScVal(BigInt(123_456), { type: 'i128' }),
      },
    } as never);

    const view = await service.getAccruedFees(VALID_TOKEN);

    expect(view).toEqual({
      token: VALID_TOKEN,
      accruedFees: '123456',
      contractId: CONTRACT_ID,
      network: 'testnet',
    });
    expect(simulateTransaction).toHaveBeenCalledTimes(1);
  });

  it('returns zero for a null return value', async () => {
    simulateTransaction.mockResolvedValue({
      result: { retval: null },
    } as never);

    const view = await service.getAccruedFees(VALID_TOKEN);
    expect(view.accruedFees).toBe('0');
  });

  it('caches the balance per token within the TTL window', async () => {
    simulateTransaction.mockResolvedValue({
      result: {
        retval: StellarSdk.nativeToScVal(BigInt(500), { type: 'i128' }),
      },
    } as never);

    const first = await service.getAccruedFees(VALID_TOKEN);
    const second = await service.getAccruedFees(VALID_TOKEN);

    expect(first.accruedFees).toBe('500');
    expect(second.accruedFees).toBe('500');
    // Cached — the RPC was simulated only once.
    expect(simulateTransaction).toHaveBeenCalledTimes(1);
  });

  it('rejects a malformed token address with BadRequestException', async () => {
    await expect(service.getAccruedFees('not-an-address')).rejects.toBeInstanceOf(
      BadRequestException,
    );
    expect(simulateTransaction).not.toHaveBeenCalled();
  });

  it('throws NotFoundException when QUICKEX_CONTRACT_ID is not configured', async () => {
    const previous = process.env.QUICKEX_CONTRACT_ID;
    delete process.env.QUICKEX_CONTRACT_ID;
    configGet.mockImplementation((key: string) =>
      key === 'stellar' ? stellarConfig : undefined,
    );

    await expect(service.getAccruedFees(VALID_TOKEN)).rejects.toBeInstanceOf(
      NotFoundException,
    );

    if (previous === undefined) delete process.env.QUICKEX_CONTRACT_ID;
    else process.env.QUICKEX_CONTRACT_ID = previous;
  });

  it('propagates RPC simulation errors instead of masking them', async () => {
    simulateTransaction.mockResolvedValue({
      error: 'HostFunctionError: contract invocation failed',
    } as never);

    await expect(service.getAccruedFees(VALID_TOKEN)).rejects.toThrow(
      /simulation error/i,
    );
  });
});
