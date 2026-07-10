import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import type { Request } from 'express';

import { ContractAllowlistService } from './contract-allowlist.service';

export const CONTRACT_METHOD_NOT_ALLOWED_CODE = 'CONTRACT_METHOD_NOT_ALLOWED';

/**
 * Blocks transaction requests targeting a contract/method pair that is not
 * present in the configured allowlist (see ContractAllowlistService).
 *
 * Expects the request body to carry `contractId` and `method` fields, as
 * produced by ComposeTransactionDto / SimulateOperationDto.
 */
@Injectable()
export class ContractMethodAllowlistGuard implements CanActivate {
  constructor(private readonly allowlist: ContractAllowlistService) {}

  canActivate(ctx: ExecutionContext): boolean {
    const req = ctx.switchToHttp().getRequest<Request>();
    const body = req.body as { contractId?: string; method?: string } | undefined;

    // No contractId/method on this route: nothing to enforce (e.g. submit-signed-xdr).
    if (!body?.contractId || !body?.method) return true;

    if (this.allowlist.isAllowed(body.contractId, body.method)) return true;

    throw new ForbiddenException({
      code: CONTRACT_METHOD_NOT_ALLOWED_CODE,
      message: `Method "${body.method}" is not allowed for contract "${body.contractId}"`,
      contractId: body.contractId,
      method: body.method,
    });
  }
}
