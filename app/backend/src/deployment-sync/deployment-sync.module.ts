import { Module } from '@nestjs/common';

import { ApiKeysModule } from '../api-keys/api-keys.module';
import { AuditModule } from '../audit/audit.module';
import { SupabaseModule } from '../supabase/supabase.module';
import { BranchDeploymentRepository } from './deployment-sync.repository';
import { BranchDeploymentService } from './deployment-sync.service';
import { BranchDeploymentController } from './deployment-sync.controller';

@Module({
  imports: [ApiKeysModule, AuditModule, SupabaseModule],
  controllers: [BranchDeploymentController],
  providers: [BranchDeploymentRepository, BranchDeploymentService],
  exports: [BranchDeploymentService],
})
export class DeploymentSyncModule {}
