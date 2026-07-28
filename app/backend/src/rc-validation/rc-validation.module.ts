import { Module } from "@nestjs/common";

import { ApiKeysModule } from "../api-keys/api-keys.module";
import { ApiKeyGuard } from "../auth/guards/api-key.guard";
import { HealthModule } from "../health/health.module";
import { ContractsModule } from "../contracts/contracts.module";
import { IndexerLagModule } from "../indexer-lag";
import { EnvironmentParityModule } from "../environment-parity/environment-parity.module";
import { RcValidationController } from "./rc-validation.controller";
import { RcValidationService } from "./rc-validation.service";

@Module({
  imports: [
    ApiKeysModule,
    HealthModule,
    ContractsModule,
    IndexerLagModule,
    EnvironmentParityModule,
  ],
  controllers: [RcValidationController],
  providers: [RcValidationService, ApiKeyGuard],
})
export class RcValidationModule {}
