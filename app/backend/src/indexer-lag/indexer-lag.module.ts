import { Module } from "@nestjs/common";
import { APP_GUARD } from "@nestjs/core";
import { IndexerLagService } from "./indexer-lag.service";
import { IndexerLagGuard } from "./indexer-lag.guard";
import { IngestionModule } from "../ingestion/ingestion.module";
import { AuditModule } from "../audit/audit.module";
import { MetricsModule } from "../metrics/metrics.module";

@Module({
  imports: [IngestionModule, AuditModule, MetricsModule],
  providers: [
    IndexerLagService,
    {
      provide: APP_GUARD,
      useClass: IndexerLagGuard,
    },
  ],
  exports: [IndexerLagService],
})
export class IndexerLagModule {}
