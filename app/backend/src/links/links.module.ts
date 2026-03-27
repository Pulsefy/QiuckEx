import { Module } from '@nestjs/common';
import { LinksController } from './links.controller';
import { LinksService } from './links.service';
import { RecurringPaymentsController } from './recurring-payments.controller';
import { RecurringPaymentsService } from './recurring-payments.service';
import { RecurringPaymentsScheduler } from './recurring-payments.scheduler';
import { RecurringPaymentsRepository } from './recurring-payments.repository';
import { RecurringPaymentProcessor } from '../stellar/recurring-payment-processor';
import { SupabaseModule } from '../supabase/supabase.module';
import { StellarModule } from '../stellar/stellar.module';

@Module({
  controllers: [LinksController, RecurringPaymentsController],
  providers: [
    LinksService,
    RecurringPaymentsService,
    RecurringPaymentsScheduler,
    RecurringPaymentsRepository,
    RecurringPaymentProcessor,
  ],
  exports: [LinksService, RecurringPaymentsService],
  imports: [SupabaseModule, StellarModule],
})
export class LinksModule {}
