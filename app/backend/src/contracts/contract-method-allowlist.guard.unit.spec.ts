import { ExecutionContext, ForbiddenException } from '@nestjs/common';

import {
  ContractMethodAllowlistGuard,
  CONTRACT_METHOD_NOT_ALLOWED_CODE,
} from './contract-method-allowlist.guard';
import { ContractAllowlistService } from './contract-allowlist.service';

function makeCtx(body: unknown): ExecutionContext {
  return {
    switchToHttp: () => ({
      getRequest: () => ({ body }),
    }),
  } as unknown as ExecutionContext;
}

describe('ContractMethodAllowlistGuard', () => {
  it('allows the request through when contractId/method are missing from the body', () => {
    const allowlist = { isAllowed: jest.fn() } as unknown as ContractAllowlistService;
    const guard = new ContractMethodAllowlistGuard(allowlist);

    expect(guard.canActivate(makeCtx({}))).toBe(true);
    expect(allowlist.isAllowed).not.toHaveBeenCalled();
  });

  it('allows the request when the allowlist permits the contract/method pair', () => {
    const allowlist = {
      isAllowed: jest.fn().mockReturnValue(true),
    } as unknown as ContractAllowlistService;
    const guard = new ContractMethodAllowlistGuard(allowlist);

    expect(guard.canActivate(makeCtx({ contractId: 'CABC', method: 'swap' }))).toBe(true);
    expect(allowlist.isAllowed).toHaveBeenCalledWith('CABC', 'swap');
  });

  it('throws a ForbiddenException with a stable error code when the pair is not allowed', () => {
    const allowlist = {
      isAllowed: jest.fn().mockReturnValue(false),
    } as unknown as ContractAllowlistService;
    const guard = new ContractMethodAllowlistGuard(allowlist);

    try {
      guard.canActivate(makeCtx({ contractId: 'CABC', method: 'withdraw' }));
      fail('expected ForbiddenException to be thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(ForbiddenException);
      const response = (error as ForbiddenException).getResponse() as { code: string };
      expect(response.code).toBe(CONTRACT_METHOD_NOT_ALLOWED_CODE);
    }
  });
});
