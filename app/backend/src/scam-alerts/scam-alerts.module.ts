import { Module } from "@nestjs/common";
import { TransactionsModule } from "../transactions/transactions.module";
import { ScamAlertsController } from "./scam-alerts.controller";
import { ScamAlertsService } from "./scam-alerts.service";

@Module({
  imports: [TransactionsModule],
  controllers: [ScamAlertsController],
  providers: [ScamAlertsService],
  exports: [ScamAlertsService],
})
export class ScamAlertsModule {}