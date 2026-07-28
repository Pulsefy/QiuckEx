import { SetMetadata } from '@nestjs/common';

export const REQUIRES_FLAG_KEY = 'requires_flag';

/**
 * Marks a controller or handler as requiring a feature flag to be enabled.
 * The NetworkSafetyGuard enforces this on every request.
 *
 * Usage:
 *   @RequiresFlag('mainnet.refunds')
 *   @Post('refunds')
 *   async initiateRefund(...) {}
 */
export const RequiresFlag = (flagKey: string) =>
  SetMetadata(REQUIRES_FLAG_KEY, flagKey);
