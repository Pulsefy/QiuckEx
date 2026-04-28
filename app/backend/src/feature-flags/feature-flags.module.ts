import { Module } from '@nestjs/common';

import { AuditModule } from '../audit/audit.module';
import { SupabaseModule } from '../supabase/supabase.module';
import { FeatureFlagsController } from './feature-flags.controller';
import { FeatureFlagsService } from './feature-flags.service';

@Module({
  imports: [SupabaseModule, AuditModule],
  controllers: [FeatureFlagsController],
  providers: [FeatureFlagsService],
  exports: [FeatureFlagsService],
})
export class FeatureFlagsModule {}
