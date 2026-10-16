import { ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import {
  ContractCompatibilityGuard,
  CONTRACT_COMPATIBILITY_FLOW_KEY,
} from './contract-compatibility.guard';
import { ContractCompatibilityService } from './contract-compatibility.service';

describe('ContractCompatibilityGuard', () => {
  let guard: ContractCompatibilityGuard;
  let mockService: jest.Mocked<Partial<ContractCompatibilityService>>;
  let mockReflector: jest.Mocked<Partial<Reflector>>;

  beforeEach(() => {
    mockService = {
      extractClientAssertionFromHeaders: jest.fn().mockReturnValue({}),
      validateWriteCompatibility: jest.fn().mockResolvedValue({
        contractName: 'quickex',
        network: 'testnet',
        contractId: 'CD2J6K7T3YJ77QXZP3ACTIVE',
        contractVersion: 1,
        schemaVersion: '1.0.0',
        schemaCompatibility: { min: '1.0.0', max: '2.0.0' },
        flow: 'pay_initiation',
        compatible: true,
        requirements: {
          flow: 'pay_initiation',
          contractName: 'quickex',
          minContractVersion: 1,
          maxContractVersion: 100_000,
          schemaCompatibility: { min: '1.0.0', max: '2.0.0' },
          supportedWriteMethods: ['deposit'],
        },
      }),
    };

    mockReflector = {
      getAllAndOverride: jest.fn().mockReturnValue('pay_initiation'),
    };

    guard = new ContractCompatibilityGuard(
      mockService as unknown as ContractCompatibilityService,
      mockReflector as unknown as Reflector,
    );
  });

  function createMockExecutionContext(req: Record<string, unknown>): ExecutionContext {
    return {
      switchToHttp: () => ({
        getRequest: () => req,
        getResponse: () => ({}),
        getNext: () => ({}),
      }),
      getHandler: () => ({}),
      getClass: () => ({}),
    } as unknown as ExecutionContext;
  }

  it('validates write compatibility with defaults and attaches metadata to request', async () => {
    const req = { headers: {}, body: {} };
    const ctx = createMockExecutionContext(req);

    const canActivate = await guard.canActivate(ctx);
    expect(canActivate).toBe(true);
    expect(mockService.validateWriteCompatibility).toHaveBeenCalledWith({
      flow: 'pay_initiation',
      contractName: 'quickex',
      method: undefined,
      contractId: undefined,
      contractVersion: undefined,
      schemaVersion: undefined,
    });
    expect(req).toHaveProperty('contractCompatibility');
  });

  it('merges assertions from headers and body with body taking precedence', async () => {
    mockService.extractClientAssertionFromHeaders = jest.fn().mockReturnValue({
      contractVersion: 1,
      schemaVersion: '1.0.0',
      contractId: 'HEADER_CONTRACT_ID',
    });

    const req = {
      headers: {
        'x-contract-version': '1',
        'x-contract-schema-version': '1.0.0',
        'x-contract-id': 'HEADER_CONTRACT_ID',
      },
      body: {
        contractId: 'BODY_CONTRACT_ID',
        contractVersion: 2,
        schemaVersion: '1.2.0',
        method: 'deposit',
      },
    };
    const ctx = createMockExecutionContext(req);

    const canActivate = await guard.canActivate(ctx);
    expect(canActivate).toBe(true);
    expect(mockService.validateWriteCompatibility).toHaveBeenCalledWith({
      flow: 'pay_initiation',
      contractName: 'quickex',
      method: 'deposit',
      contractId: 'BODY_CONTRACT_ID',
      contractVersion: 2,
      schemaVersion: '1.2.0',
    });
  });

  it('respects flow metadata from Reflector', async () => {
    mockReflector.getAllAndOverride = jest.fn().mockReturnValue('link');

    const req = { headers: {}, body: {} };
    const ctx = createMockExecutionContext(req);

    await guard.canActivate(ctx);
    expect(mockReflector.getAllAndOverride).toHaveBeenCalledWith(
      CONTRACT_COMPATIBILITY_FLOW_KEY,
      expect.any(Array),
    );
    expect(mockService.validateWriteCompatibility).toHaveBeenCalledWith(
      expect.objectContaining({ flow: 'link' }),
    );
  });
});
