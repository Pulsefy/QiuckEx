import { Module } from '@nestjs/common';
import { ApiKeyGuard } from './guards/api-key.guard';
import { CustomThrottlerGuard } from './guards/custom-throttler.guard';

@Module({
  providers: [ApiKeyGuard, CustomThrottlerGuard],
  exports: [ApiKeyGuard, CustomThrottlerGuard],
})
export class AuthModule {}
