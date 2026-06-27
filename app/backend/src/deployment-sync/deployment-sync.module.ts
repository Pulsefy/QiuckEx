import { Module } from '@nestjs/common';
import { DeploymentSyncService } from './deployment-sync.service';
import { DeploymentSyncController } from './deployment-sync.controller';
import { SupabaseModule } from '../supabase/supabase.module';
import { AuthModule } from '../auth/auth.module';

@Module({
  imports: [SupabaseModule, AuthModule],
  controllers: [DeploymentSyncController],
  providers: [DeploymentSyncService],
  exports: [DeploymentSyncService],
})
export class DeploymentSyncModule {}
