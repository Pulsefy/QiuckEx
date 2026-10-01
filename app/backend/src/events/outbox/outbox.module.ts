import { Module } from "@nestjs/common";

import { MetricsModule } from "../../metrics/metrics.module";
import { SupabaseModule } from "../../supabase/supabase.module";
import { OutboxDispatcher } from "./outbox.dispatcher";
import { OutboxRepository } from "./outbox.repository";
import { OutboxService } from "./outbox.service";

@Module({
  imports: [MetricsModule, SupabaseModule],
  providers: [OutboxRepository, OutboxService, OutboxDispatcher],
  exports: [OutboxService, OutboxRepository],
})
export class OutboxModule {}
