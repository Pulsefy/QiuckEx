import { Module } from '@nestjs/common';
import { SupportBundleService } from './support-bundle.service';
import { SupportBundleController } from './support-bundle.controller';
import { ContractRegistryModule } from '../contracts/contract-registry.module';
import { IndexerLagModule } from '../indexer-lag/indexer-lag.module';
import { IngestionModule } from '../ingestion/ingestion.module';
import { AuditModule } from '../audit/audit.module';

@Module({
  imports: [ContractRegistryModule, IndexerLagModule, IngestionModule, AuditModule],
  controllers: [SupportBundleController],
  providers: [SupportBundleService],
  exports: [SupportBundleService],
})
export class SupportBundleModule {}
