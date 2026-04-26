import { Module, forwardRef } from "@nestjs/common";

import { SupabaseModule } from "../supabase/supabase.module";
import { JobQueueModule } from "../job-queue/job-queue.module";
import { CursorRepository } from "./cursor.repository";
import { EscrowEventRepository } from "./escrow-event.repository";
import { SorobanEventParser } from "./soroban-event.parser";
import { StellarIngestionService } from "./stellar-ingestion.service";
import { IngestionBootstrapService } from "./ingestion-bootstrap.service";

@Module({
  imports: [
    SupabaseModule,
    forwardRef(() => JobQueueModule),
  ],
  providers: [
    CursorRepository,
    EscrowEventRepository,
    SorobanEventParser,
    StellarIngestionService,
    IngestionBootstrapService,
  ],
  exports: [StellarIngestionService, SorobanEventParser, CursorRepository, EscrowEventRepository],
})
export class IngestionModule {}
