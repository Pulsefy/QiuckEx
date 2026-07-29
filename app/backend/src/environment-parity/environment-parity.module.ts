import { Module } from "@nestjs/common";
import { EnvironmentParityService } from "./environment-parity.service";
import { EnvironmentParityController } from "./environment-parity.controller";
import { MetricsModule } from "../metrics/metrics.module";
import { StagingSeedService } from "./staging-seed.service";
import { SupabaseModule } from "../supabase/supabase.module";

@Module({
  imports: [MetricsModule, SupabaseModule],
  providers: [EnvironmentParityService, StagingSeedService],
  controllers: [EnvironmentParityController],
  exports: [EnvironmentParityService, StagingSeedService],
})
export class EnvironmentParityModule {}
