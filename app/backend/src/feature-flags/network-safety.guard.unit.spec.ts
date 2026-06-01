import { ExecutionContext, ServiceUnavailableException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';

import { NetworkSafetyGuard } from './network-safety.guard';
import { FeatureFlagsService } from './feature-flags.service';
import { AuditService } from '../audit/audit.service';
import { AppConfigService } from '../config';

function makeCtx(userId?: string): ExecutionContext {
  return {
    getHandler: () => ({}),
    getClass: () => ({}),
    switchToHttp: () => ({
      getRequest: () => ({
        headers: userId ? { 'x-user-id': userId } : {},
        path: '/admin/refunds',
        method: 'POST',
      }),
    }),
  } as unknown as ExecutionContext;
}

function buildGuard(
  network: 'testnet' | 'mainnet',
  flagEnabled: boolean,
  flagKey: string | undefined = 'mainnet.refunds',
) {
  // Use a special sentinel to allow passing undefined explicitly if desired
  const effectiveFlagKey = flagKey === 'SENTINEL_UNDEFINED' ? undefined : flagKey;

  const reflector = {
    getAllAndOverride: jest.fn().mockReturnValue(effectiveFlagKey),
  } as unknown as Reflector;

  const config = {
    isTestnet: network === 'testnet',
    network,
  } as unknown as AppConfigService;

  const flags = {
    evaluateFlag: jest.fn().mockResolvedValue({
      key: flagKey,
      enabled: flagEnabled,
      reason: flagEnabled ? 'enabled' : 'disabled',
      source: 'bootstrap',
    }),
  } as unknown as FeatureFlagsService;

  const audit = { log: jest.fn().mockResolvedValue(undefined) } as unknown as AuditService;

  return { guard: new NetworkSafetyGuard(reflector, config, flags, audit), flags, audit };
}

describe('NetworkSafetyGuard', () => {
  it('passes through when no @RequiresFlag decorator is present', async () => {
    const { guard } = buildGuard('mainnet', false, 'SENTINEL_UNDEFINED');
    await expect(guard.canActivate(makeCtx())).resolves.toBe(true);
  });

  it('passes through on testnet regardless of flag state', async () => {
    const { guard } = buildGuard('testnet', false);
    await expect(guard.canActivate(makeCtx())).resolves.toBe(true);
  });

  it('allows on mainnet when flag is enabled', async () => {
    const { guard } = buildGuard('mainnet', true);
    await expect(guard.canActivate(makeCtx('user-1'))).resolves.toBe(true);
  });

  it('blocks on mainnet when flag is disabled and audits the attempt', async () => {
    const { guard, audit } = buildGuard('mainnet', false);
    await expect(guard.canActivate(makeCtx('user-1'))).rejects.toThrow(
      ServiceUnavailableException,
    );
    expect(audit.log).toHaveBeenCalledWith(
      'user-1',
      'network_safety_gate.blocked',
      'mainnet.refunds',
      expect.objectContaining({ network: 'mainnet' }),
    );
  });

  it('uses "anonymous" actor when no x-user-id header', async () => {
    const { guard, audit } = buildGuard('mainnet', false);
    await expect(guard.canActivate(makeCtx())).rejects.toThrow(ServiceUnavailableException);
    expect(audit.log).toHaveBeenCalledWith(
      'anonymous',
      'network_safety_gate.blocked',
      'mainnet.refunds',
      expect.anything(),
    );
  });

  it('error body contains MAINNET_GATE_BLOCKED code and flag key', async () => {
    const { guard } = buildGuard('mainnet', false);
    try {
      await guard.canActivate(makeCtx());
    } catch (err) {
      const body = (err as ServiceUnavailableException).getResponse() as Record<string, unknown>;
      expect(body.error).toBe('MAINNET_GATE_BLOCKED');
      expect(body.flag).toBe('mainnet.refunds');
    }
  });
});
