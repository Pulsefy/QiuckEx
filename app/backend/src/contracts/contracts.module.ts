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
import { ContractSpecController } from './contract-spec.controller';
import { ContractSpecService } from './contract-spec.service';
import { SmokeScenariosController } from './smoke-scenarios/smoke-scenarios.controller';
import { SmokeScenariosService } from './smoke-scenarios/smoke-scenarios.service';
import {
  CONTRACT_CONFIG_READER,
  CONTRACT_REGISTRY_READER,
  ContractCompatibilityService,
} from './contract-compatibility.service';
import { ContractCompatibilityGuard } from './contract-compatibility.guard';
import { AppConfigService } from '../config/app-config.service';

@Module({
  imports: [ApiKeysModule, AuditModule, SupabaseModule],
  controllers: [
    ContractRegistryController,
    ContractChangeWebhooksController,
    ContractViewsController,
    ContractAllowlistController,
    DeploymentArtifactsController,
    ContractSpecController, // Add new controller
    SmokeScenariosController,
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
    ContractSpecService, // Add new service
    SmokeScenariosService,
    {
      provide: CONTRACT_REGISTRY_READER,
      useExisting: ContractRegistryService,
    },
    {
      provide: CONTRACT_CONFIG_READER,
      useFactory: (config?: AppConfigService) => config,
      inject: [{ token: AppConfigService, optional: true }],
    },
    ContractCompatibilityService,
    ContractCompatibilityGuard,
  ],
  exports: [
    ContractRegistryService,
    ContractViewsService,
    ContractAllowlistService,
    ContractMethodAllowlistGuard,
    ContractSpecService, // Export new service
    SmokeScenariosService,
    CONTRACT_REGISTRY_READER,
    CONTRACT_CONFIG_READER,
    ContractCompatibilityService,
    ContractCompatibilityGuard,
  ],
})
export class ContractsModule {}