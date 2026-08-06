import { Module } from '@nestjs/common';
import { ApiKeyGuard } from './guards/api-key.guard';
import { CustomThrottlerGuard } from './guards/custom-throttler.guard';
import { ApiKeysModule } from '../api-keys/api-keys.module';
import { MetricsModule } from '../metrics/metrics.module';

@Module({
  imports: [ApiKeysModule, MetricsModule],
  providers: [ApiKeyGuard, CustomThrottlerGuard],
  exports: [ApiKeyGuard, CustomThrottlerGuard],
})
export class AuthModule {}
