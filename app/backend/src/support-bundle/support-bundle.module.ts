import { Module } from '@nestjs/common';
import { SupportBundleService } from './support-bundle.service';
import { SupportBundleController } from './support-bundle.controller';
import { SupportBundleReferenceService } from './support-bundle-reference.service';
import { SupportBundleReferenceController } from './support-bundle-reference.controller';
import { ContractsModule } from '../contracts/contracts.module';
import { IndexerLagModule } from '../indexer-lag/indexer-lag.module';
import { IngestionModule } from '../ingestion/ingestion.module';
import { AuditModule } from '../audit/audit.module';
import { SupabaseModule } from '../supabase/supabase.module';
import { ApiKeysModule } from '../api-keys/api-keys.module';

@Module({
  imports: [
    ContractsModule,
    IndexerLagModule,
    IngestionModule,
    AuditModule,
    SupabaseModule,
    ApiKeysModule,
  ],
  controllers: [SupportBundleController, SupportBundleReferenceController],
  providers: [SupportBundleService, SupportBundleReferenceService],
  exports: [SupportBundleService, SupportBundleReferenceService],
})
export class SupportBundleModule {}
