import { Module } from '@nestjs/common';

import { ContractsModule } from '../contracts/contracts.module';
import { FeatureFlagsModule } from '../feature-flags/feature-flags.module';
import { PreviewScopeModule } from '../preview-scope/preview-scope.module';
import { RuntimeConfigController } from './runtime-config.controller';
import { RuntimeConfigService } from './runtime-config.service';

@Module({
  imports: [FeatureFlagsModule, ContractsModule, PreviewScopeModule],
  controllers: [RuntimeConfigController],
  providers: [RuntimeConfigService],
  exports: [RuntimeConfigService],
})
export class RuntimeConfigModule {}
