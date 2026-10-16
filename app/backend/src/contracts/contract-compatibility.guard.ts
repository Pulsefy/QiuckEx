import {
  CanActivate,
  ExecutionContext,
  Injectable,
  SetMetadata,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { Request } from 'express';

import { ContractCompatibilityService } from './contract-compatibility.service';
import {
  ClientContractAssertionDto,
  ContractCompatibilityFlow,
  ContractCompatibilityMetadataDto,
} from './dto';

export const CONTRACT_COMPATIBILITY_FLOW_KEY = 'contract_compatibility_flow';

export const EnforceContractCompatibility = (
  flow: ContractCompatibilityFlow = 'pay_initiation',
) => SetMetadata(CONTRACT_COMPATIBILITY_FLOW_KEY, flow);

export interface ContractCompatibleRequest {
  headers?: Record<string, string | string[] | undefined>;
  body?: unknown;
  contractCompatibility?: ContractCompatibilityMetadataDto;
  [key: string]: unknown;
}

/**
 * Enforces contract schema and deployment version compatibility on write
 * and preflight endpoints.
 *
 * Reads optional client contract assertions from:
 * - Headers: `X-Contract-Version`, `X-Contract-Schema-Version`, `X-Contract-Id`
 * - Request body: `contractVersion`, `schemaVersion`, `contractId`, `contractCompatibility`, `method`
 */
@Injectable()
export class ContractCompatibilityGuard implements CanActivate {
  constructor(
    private readonly compatibilityService: ContractCompatibilityService,
    private readonly reflector?: Reflector,
  ) {}

  async canActivate(ctx: ExecutionContext): Promise<boolean> {
    const req = ctx.switchToHttp().getRequest<ContractCompatibleRequest>();
    const flow =
      this.reflector?.getAllAndOverride<ContractCompatibilityFlow>(
        CONTRACT_COMPATIBILITY_FLOW_KEY,
        [ctx.getHandler(), ctx.getClass()],
      ) ?? 'pay_initiation';

    const headerAssertion =
      this.compatibilityService.extractClientAssertionFromHeaders(
        req.headers ?? {},
      );

    const body = (req.body ?? {}) as {
      contractName?: string;
      contractId?: string;
      contractVersion?: number;
      schemaVersion?: string;
      method?: string;
      contractCompatibility?: ClientContractAssertionDto;
    };

    const mergedContractId =
      body.contractCompatibility?.contractId ??
      body.contractId ??
      headerAssertion.contractId;
    const mergedContractVersion =
      body.contractCompatibility?.contractVersion ??
      body.contractVersion ??
      headerAssertion.contractVersion;
    const mergedSchemaVersion =
      body.contractCompatibility?.schemaVersion ??
      body.schemaVersion ??
      headerAssertion.schemaVersion;

    const metadata = await this.compatibilityService.validateWriteCompatibility({
      flow,
      contractName: body.contractName ?? 'quickex',
      method: body.method,
      contractId: mergedContractId,
      contractVersion: mergedContractVersion,
      schemaVersion: mergedSchemaVersion,
    });

    req.contractCompatibility = metadata;
    return true;
  }
}
