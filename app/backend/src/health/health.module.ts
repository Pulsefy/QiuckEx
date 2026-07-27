import { Module } from "@nestjs/common";
import { SupabaseModule } from "../supabase/supabase.module";
import { StellarModule } from "../stellar/stellar.module";
import { JobQueueModule } from "../job-queue/job-queue.module";
import { IngestionModule } from "../ingestion/ingestion.module";
import { TransactionsModule } from "../transactions/transactions.module";
import { HealthController } from "./health.controller";
import { HealthService } from "./health.service";

@Module({
  imports: [SupabaseModule, StellarModule, JobQueueModule, IngestionModule, TransactionsModule],
  controllers: [HealthController],
  providers: [HealthService],
  exports: [HealthService],
})
export class HealthModule {}
