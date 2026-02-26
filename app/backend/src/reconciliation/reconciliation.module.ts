import { Module } from "@nestjs/common";

import { AppConfigModule } from "../config";
import { SupabaseModule } from "../supabase/supabase.module";
import { ReconciliationService } from "./reconciliation.service";
import { ReconciliationWorkerService } from "./reconciliation-worker.service";
import { ReconciliationController } from "./reconciliation.controller";

/**
 * ScheduleModule is registered once at AppModule level.
 */
@Module({
  imports: [AppConfigModule, SupabaseModule],
  providers: [ReconciliationService, ReconciliationWorkerService],
  controllers: [ReconciliationController],
  exports: [ReconciliationWorkerService],
})
export class ReconciliationModule {}
