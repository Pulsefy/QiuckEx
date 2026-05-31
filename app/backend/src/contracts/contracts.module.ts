import { Module } from '@nestjs/common';

import { ApiKeysModule } from '../api-keys/api-keys.module';
import { AuditModule } from '../audit/audit.module';
import { ApiKeyGuard } from '../auth/guards/api-key.guard';
import { SupabaseModule } from '../supabase/supabase.module';
import { ContractRegistryController } from './contract-registry.controller';
import { ContractChangeWebhooksController } from './contract-change-webhooks.controller';
import { ContractRegistryService } from './contract-registry.service';
import { ContractChangeWebhookService } from './contract-change-webhook.service';
import { ContractViewsController } from './views/contract-views.controller';
import { ContractViewsService } from './views/contract-views.service';

@Module({
  imports: [ApiKeysModule, AuditModule, SupabaseModule],
  controllers: [ContractRegistryController, ContractChangeWebhooksController, ContractViewsController],
  providers: [
    ContractRegistryService,
    ContractChangeWebhookService,
    ApiKeyGuard,
    ContractViewsService
  ],
  exports: [ContractRegistryService, ContractViewsService],
})
export class ContractsModule {}
