import { Module } from "@nestjs/common";

import { TransactionsModule } from "../transactions/transactions.module";
import { HorizonService } from "./horizon.service";
import { LinkService } from "./link.service";
import { PathPreviewService } from "./path-preview.service";
import { StellarController } from "./stellar.controller";

@Module({
  imports: [TransactionsModule],
  controllers: [StellarController],
  providers: [LinkService, HorizonService, PathPreviewService],
  exports: [LinkService, HorizonService, PathPreviewService],
})
export class StellarModule {}
