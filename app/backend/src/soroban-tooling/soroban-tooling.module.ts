import { Module } from '@nestjs/common';

import { ApiKeysModule } from '../api-keys/api-keys.module';
import { ApiKeyGuard } from '../auth/guards/api-key.guard';
import { ContractsModule } from '../contracts/contracts.module';
import { StellarModule } from '../stellar/stellar.module';
import { DeploymentService } from './deployment.service';
import { FundingHelperService } from './funding-helper.service';
import { SorobanToolingController } from './soroban-tooling.controller';
import { SupabaseModule } from '../supabase/supabase.module';
import { IngestionModule } from '../ingestion/ingestion.module';
import { MetricsModule } from '../metrics/metrics.module';
import { AuditModule } from '../audit/audit.module';
import { AppConfigModule } from '../config';
import { TestnetResetService } from './testnet-reset.service';

@Module({
  imports: [ApiKeysModule, StellarModule, ContractsModule, SupabaseModule, IngestionModule, MetricsModule, AuditModule, AppConfigModule],
  controllers: [SorobanToolingController],
  providers: [FundingHelperService, DeploymentService, ApiKeyGuard, TestnetResetService],
  exports: [FundingHelperService, DeploymentService, TestnetResetService],
})
export class SorobanToolingModule {}
