import { Module } from "@nestjs/common";

import { MetricsModule } from "../../metrics/metrics.module";
import { OutboxDispatcher } from "./outbox.dispatcher";
import { OutboxRepository } from "./outbox.repository";
import { OutboxService } from "./outbox.service";

@Module({
  imports: [MetricsModule],
  providers: [OutboxRepository, OutboxService, OutboxDispatcher],
  exports: [OutboxService, OutboxRepository],
})
export class OutboxModule {}
