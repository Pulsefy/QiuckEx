import { Module } from "@nestjs/common";
import { SupabaseModule } from "../supabase/supabase.module";
import { MetricsModule } from "../metrics/metrics.module";
import { AbuseSignalService } from "./abuse-signal.service";
import { AbuseSignalController } from "./abuse-signal.controller";
import { AbuseSignalScheduler } from "./abuse-signal.scheduler";

@Module({
  imports: [SupabaseModule, MetricsModule],
  controllers: [AbuseSignalController],
  providers: [AbuseSignalService, AbuseSignalScheduler],
  exports: [AbuseSignalService],
})
export class AbuseSignalsModule {}
