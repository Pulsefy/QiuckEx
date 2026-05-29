import { Module } from '@nestjs/common';

import { AuditModule } from '../audit/audit.module';
import { SupabaseModule } from '../supabase/supabase.module';
import { FeatureFlagsController } from './feature-flags.controller';
import { FeatureFlagsService } from './feature-flags.service';
import { NetworkSafetyGuard } from './network-safety.guard';

@Module({
  imports: [SupabaseModule, AuditModule],
  controllers: [FeatureFlagsController],
  providers: [FeatureFlagsService, NetworkSafetyGuard],
  exports: [FeatureFlagsService, NetworkSafetyGuard],
})
export class FeatureFlagsModule {}
