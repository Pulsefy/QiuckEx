import { Module } from '@nestjs/common';

import { ApiKeysModule } from '../api-keys/api-keys.module';
import { AuditModule } from '../audit/audit.module';
import { ApiKeyGuard } from '../auth/guards/api-key.guard';
import { SupabaseModule } from '../supabase/supabase.module';
import { ContractRegistryController } from './contract-registry.controller';
import { ContractChangeWebhooksController } from './contract-change-webhooks.controller';
import { ContractRegistryService } from './contract-registry.service';
import { ContractChangeWebhookService } from './contract-change-webhook.service';
import { ContractChangeWebhookDispatcher } from './contract-change-webhook.dispatcher';
import { ContractViewsController } from './views/contract-views.controller';
import { ContractViewsService } from './views/contract-views.service';
import { ContractAllowlistService } from './contract-allowlist.service';
import { ContractMethodAllowlistGuard } from './contract-method-allowlist.guard';
import { ContractAllowlistController } from './contract-allowlist.controller';
import { DeploymentArtifactsController } from './deployment-artifacts.controller';
import { DeploymentArtifactsService } from './deployment-artifacts.service';

@Module({
  imports: [ApiKeysModule, AuditModule, SupabaseModule],
  controllers: [
    ContractRegistryController,
    ContractChangeWebhooksController,
    ContractViewsController,
    ContractAllowlistController,
    DeploymentArtifactsController,
  ],
  providers: [
    ContractRegistryService,
    ContractChangeWebhookService,
    ContractChangeWebhookDispatcher,
    ApiKeyGuard,
    ContractViewsService,
    ContractAllowlistService,
    ContractMethodAllowlistGuard,
    DeploymentArtifactsService,
  ],
  exports: [
    ContractRegistryService,
    ContractViewsService,
    ContractAllowlistService,
    ContractMethodAllowlistGuard,
  ],
})
export class ContractsModule {}
