import { Module } from '@nestjs/common';

import { ApiKeysModule } from '../api-keys/api-keys.module';
import { AuditModule } from '../audit/audit.module';
import { ApiKeyGuard } from '../auth/guards/api-key.guard';
import { SupabaseModule } from '../supabase/supabase.module';
import { ContractRegistryController } from './contract-registry.controller';
import { ContractRegistryService } from './contract-registry.service';

@Module({
  imports: [ApiKeysModule, AuditModule, SupabaseModule],
  controllers: [ContractRegistryController],
  providers: [ContractRegistryService, ApiKeyGuard],
  exports: [ContractRegistryService],
})
export class ContractsModule {}
