import { Module } from "@nestjs/common";
import { SupabaseModule } from "../supabase/supabase.module";
import { StellarModule } from "../stellar/stellar.module";
import { HealthController } from "./health.controller";
import { HealthService } from "./health.service";

@Module({
  imports: [SupabaseModule, StellarModule],
  controllers: [HealthController],
  providers: [HealthService],
})
export class HealthModule {}
