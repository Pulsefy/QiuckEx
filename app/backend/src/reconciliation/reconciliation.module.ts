import { Module, forwardRef } from "@nestjs/common";

import { AppConfigModule } from "../config";
import { SupabaseModule } from "../supabase/supabase.module";
import { MetricsModule } from "../metrics/metrics.module";
import { IngestionModule } from "../ingestion/ingestion.module";
import { JobQueueModule } from "../job-queue/job-queue.module";
import { FeatureFlagsModule } from "../feature-flags/feature-flags.module";
import { AuditModule } from "../audit/audit.module";
import { PreviewScopeModule } from "../preview-scope/preview-scope.module";
import { SentryModule } from "../sentry";
import { ReconciliationService } from "./reconciliation.service";
import { ReconciliationWorkerService } from "./reconciliation-worker.service";
import { BackfillService } from "./backfill.service";
import { AutoMatchService } from "./auto-match.service";
import { UnmatchedQueueRepository } from "./unmatched-queue.repository";
import { ReconciliationRunRepository } from "./reconciliation-run.repository";
import { ReconciliationController } from "./reconciliation.controller";

@Module({
  imports: [
    AppConfigModule,
    SupabaseModule,
    MetricsModule,
    SentryModule,
    IngestionModule,
    forwardRef(() => JobQueueModule),
    FeatureFlagsModule,
    AuditModule,
    PreviewScopeModule,
  ],
  providers: [
    ReconciliationService,
    ReconciliationWorkerService,
    BackfillService,
    AutoMatchService,
    UnmatchedQueueRepository,
    ReconciliationRunRepository,
  ],
  controllers: [ReconciliationController],
  exports: [
    ReconciliationService,
    ReconciliationWorkerService,
    BackfillService,
    AutoMatchService,
    UnmatchedQueueRepository,
    ReconciliationRunRepository,
  ],
})
export class ReconciliationModule {}
