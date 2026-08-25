import { Module } from '@nestjs/common';
import { TransactionTimelineController } from './transaction-timeline.controller';
import { TransactionTimelineService } from './transaction-timeline.service';
import { SupabaseModule } from '../supabase/supabase.module';
import { TransactionsModule } from '../transactions/transactions.module';
import {
  SupabaseTransactionTimelineRepository,
  TRANSACTION_TIMELINE_REPOSITORY,
} from './transaction-timeline.repository';

@Module({
  imports: [
    SupabaseModule,
    TransactionsModule,   // provides HorizonService
  ],
  controllers: [TransactionTimelineController],
  providers: [
    TransactionTimelineService,
    {
      provide: TRANSACTION_TIMELINE_REPOSITORY,
      useClass: SupabaseTransactionTimelineRepository,
    },
  ],
  exports: [TransactionTimelineService],
})
export class TransactionTimelineModule {}
