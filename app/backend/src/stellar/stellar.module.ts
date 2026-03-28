import { Module } from "@nestjs/common";

import { TransactionsModule } from "../transactions/transactions.module";
import { HorizonService } from "./horizon.service";
import { LinkService } from "./link.service";
import { PathPreviewService } from "./path-preview.service";
import { StellarController } from "./stellar.controller";
import { ApiKeysModule } from "../api-keys/api-keys.module";
import { ApiKeyGuard } from "../auth/guards/api-key.guard";

@Module({
  imports: [TransactionsModule, ApiKeysModule],
  controllers: [StellarController],
  providers: [LinkService, HorizonService, PathPreviewService, ApiKeyGuard],
  exports: [LinkService, HorizonService, PathPreviewService],
})
export class StellarModule {}
