import { Module } from "@nestjs/common";
import { TransactionsController } from "./transactions.controller";
import { HorizonService } from "./horizon.service";
import { AppConfigModule } from "../config";
import { TransactionsService } from "./transaction.service";
import { SorobanRpcService } from "./soroban-rpc.service";
import { ApiKeysModule } from "../api-keys/api-keys.module";
import { ApiKeyGuard } from "../auth/guards/api-key.guard";

@Module({
  imports: [AppConfigModule, ApiKeysModule],
  controllers: [TransactionsController],
  providers: [HorizonService, TransactionsService, SorobanRpcService, ApiKeyGuard],
  exports: [HorizonService, TransactionsService],
})
export class TransactionsModule {}
