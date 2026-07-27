import { Module } from "@nestjs/common";

import { OperationsController } from "./operations.controller";
import { OperationsService } from "./operations.service";

import { IndexerLagModule } from "../indexer-lag/indexer-lag.module";
import { AuditModule } from "../audit/audit.module";
import { NotificationsModule } from "../notifications/notifications.module";

@Module({
  imports: [
    IndexerLagModule,
    AuditModule,
    NotificationsModule,
  ],
  controllers: [OperationsController],
  providers: [OperationsService],
})
export class OperationsModule {}