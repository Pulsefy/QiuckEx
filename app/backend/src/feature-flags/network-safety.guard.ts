import {
  CanActivate,
  ExecutionContext,
  Injectable,
  Logger,
  ServiceUnavailableException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { Request } from 'express';

import { AppConfigService } from '../config';
import { AuditService } from '../audit/audit.service';
import {
  CONTRACT_WRITES_DISABLED_CODE,
  CONTRACT_WRITES_DISABLED_MESSAGE,
  TESTNET_CONTRACT_WRITES_FLAG,
} from './contract-write-kill-switch.constants';
import { FeatureFlagsService } from './feature-flags.service';
import { REQUIRES_FLAG_KEY } from './requires-flag.decorator';

/**
 * Guard that enforces network-aware feature flag gating on high-risk flows.
 *
 * Contract write routes use a fresh flag read so the testnet kill switch takes
 * effect across instances without waiting for the normal feature flag cache.
 */
@Injectable()
export class NetworkSafetyGuard implements CanActivate {
  private readonly logger = new Logger(NetworkSafetyGuard.name);

  constructor(
    private readonly reflector: Reflector,
    private readonly config: AppConfigService,
    private readonly flags: FeatureFlagsService,
    private readonly audit: AuditService,
  ) {}

  async canActivate(ctx: ExecutionContext): Promise<boolean> {
    const flagKey = this.reflector.getAllAndOverride<string | undefined>(
      REQUIRES_FLAG_KEY,
      [ctx.getHandler(), ctx.getClass()],
    );

    // No flag requirement on this route: always allow.
    if (!flagKey) return true;

    const req = ctx.switchToHttp().getRequest<Request>();
    const userId = (req.headers['x-user-id'] as string | undefined)?.trim();

    if (flagKey === TESTNET_CONTRACT_WRITES_FLAG) {
      if (!this.config.isTestnet) return true;

      const result = await this.flags.evaluateFlagFresh(flagKey, { userId });

      if (result.enabled) return true;

      await this.audit.log(
        userId ?? 'anonymous',
        'network_safety_gate.blocked',
        flagKey,
        {
          reason: result.reason,
          network: this.config.network,
          path: req.path,
          method: req.method,
        },
      );

      this.logger.warn(
        `NetworkSafetyGuard blocked ${req.method} ${req.path} ` +
          `(flag=${flagKey} reason=${result.reason} network=testnet)`,
      );

      throw new ServiceUnavailableException({
        code: CONTRACT_WRITES_DISABLED_CODE,
        error: CONTRACT_WRITES_DISABLED_CODE,
        flag: flagKey,
        reason: result.reason,
        message: CONTRACT_WRITES_DISABLED_MESSAGE,
      });
    }

    // Testnet remains open for all non-write routes and non-testnet kill switches.
    if (this.config.isTestnet) return true;

    const result = await this.flags.evaluateFlag(flagKey, { userId });

    if (result.enabled) return true;

    // Blocked on mainnet: audit and reject.
    await this.audit.log(
      userId ?? 'anonymous',
      'network_safety_gate.blocked',
      flagKey,
      {
        reason: result.reason,
        network: this.config.network,
        path: req.path,
        method: req.method,
      },
    );

    this.logger.warn(
      `NetworkSafetyGuard blocked ${req.method} ${req.path} ` +
        `(flag=${flagKey} reason=${result.reason} network=mainnet)`,
    );

    throw new ServiceUnavailableException({
      error: 'MAINNET_GATE_BLOCKED',
      flag: flagKey,
      reason: result.reason,
      message: `This action is disabled on mainnet. Enable flag "${flagKey}" to proceed.`,
    });
  }
}
