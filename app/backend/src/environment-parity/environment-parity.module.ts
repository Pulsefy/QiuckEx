import { Module } from "@nestjs/common";
import { EnvironmentParityService } from "./environment-parity.service";
import { EnvironmentParityController } from "./environment-parity.controller";
import { MetricsModule } from "../metrics/metrics.module";
import { StagingSeedService } from "./staging-seed.service";

@Module({
  imports: [MetricsModule],
  providers: [EnvironmentParityService, StagingSeedService],
  controllers: [EnvironmentParityController],
  exports: [EnvironmentParityService, StagingSeedService],
})
export class EnvironmentParityModule {}
