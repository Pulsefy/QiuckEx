import { Module } from "@nestjs/common";
import { TransactionsController } from "./transactions.controller";
import { HorizonService } from "./horizon.service";
import { AppConfigModule } from "../config";
import { TransactionsService } from "./transaction.service";
import { SorobanRpcService } from "./soroban-rpc.service";

@Module({
  imports: [AppConfigModule],
  controllers: [TransactionsController],
  providers: [HorizonService, TransactionsService, SorobanRpcService],
  exports: [HorizonService, TransactionsService],
})
export class TransactionsModule {}
