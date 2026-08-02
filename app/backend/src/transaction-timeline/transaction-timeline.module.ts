import { Module } from '@nestjs/common';
import { TransactionTimelineController } from './transaction-timeline.controller';
import { TransactionTimelineService } from './transaction-timeline.service';
import { SupabaseModule } from '../supabase/supabase.module';
import { TransactionsModule } from '../transactions/transactions.module';

@Module({
  imports: [
    SupabaseModule,
    TransactionsModule,   // provides HorizonService
  ],
  controllers: [TransactionTimelineController],
  providers: [TransactionTimelineService],
  exports: [TransactionTimelineService],
})
export class TransactionTimelineModule {}
