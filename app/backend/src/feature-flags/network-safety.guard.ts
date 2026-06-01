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
import { FeatureFlagsService } from './feature-flags.service';
import { REQUIRES_FLAG_KEY } from './requires-flag.decorator';

/**
 * Guard that enforces network-aware feature flag gating on high-risk flows.
 *
 * Behaviour:
 *  - If the handler has no @RequiresFlag() decorator → pass through.
 *  - On testnet → pass through (development-safe default).
 *  - On mainnet → evaluate the flag. If disabled (or missing) → 503.
 *    The allowedUsers list on the flag enables early-access per org/user.
 *
 * All blocked requests are audited so they are visible in admin tooling.
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

    // No flag requirement on this route → always allow.
    if (!flagKey) return true;

    // Testnet is always safe → allow.
    if (this.config.isTestnet) return true;

    const req = ctx.switchToHttp().getRequest<Request>();
    const userId = (req.headers['x-user-id'] as string | undefined)?.trim();

    const result = await this.flags.evaluateFlag(flagKey, { userId });

    if (result.enabled) return true;

    // Blocked on mainnet — audit and reject.
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
