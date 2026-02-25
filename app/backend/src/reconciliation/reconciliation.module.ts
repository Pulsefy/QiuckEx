import { Module } from '@nestjs/common';
import { ScheduleModule } from '@nestjs/schedule';

import { AppConfigModule } from '../config';
import { SupabaseModule } from '../supabase/supabase.module';
import { ReconciliationService } from './reconciliation.service';
import { ReconciliationWorkerService } from './reconciliation-worker.service';
import { ReconciliationController } from './reconciliation.controller';

@Module({
  imports: [
    ScheduleModule.forRoot(),
    AppConfigModule,
    SupabaseModule,
  ],
  providers: [ReconciliationService, ReconciliationWorkerService],
  controllers: [ReconciliationController],
  exports: [ReconciliationWorkerService],
})
export class ReconciliationModule {}
