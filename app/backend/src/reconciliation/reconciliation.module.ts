import { Module, forwardRef } from "@nestjs/common";

import { AppConfigModule } from "../config";
import { SupabaseModule } from "../supabase/supabase.module";
import { MetricsModule } from "../metrics/metrics.module";
import { IngestionModule } from "../ingestion/ingestion.module";
import { JobQueueModule } from "../job-queue/job-queue.module";
import { ReconciliationService } from "./reconciliation.service";
import { ReconciliationWorkerService } from "./reconciliation-worker.service";
import { BackfillService } from "./backfill.service";
import { AutoMatchService } from "./auto-match.service";
import { UnmatchedQueueRepository } from "./unmatched-queue.repository";
import { ReconciliationController } from "./reconciliation.controller";

/**
 * ScheduleModule is registered once at AppModule level.
 */
@Module({
  imports: [
    AppConfigModule,
    SupabaseModule,
    MetricsModule,
    IngestionModule,
    forwardRef(() => JobQueueModule),
  ],
  providers: [
    ReconciliationService,
    ReconciliationWorkerService,
    BackfillService,
    AutoMatchService,
    UnmatchedQueueRepository,
  ],
  controllers: [ReconciliationController],
  exports: [
    ReconciliationService,
    ReconciliationWorkerService,
    BackfillService,
    AutoMatchService,
    UnmatchedQueueRepository,
  ],
})
export class ReconciliationModule {}
