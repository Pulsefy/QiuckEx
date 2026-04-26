import { Module } from '@nestjs/common';
import { LinksController } from './links.controller';
import { LinksService } from './links.service';
import { BulkPaymentLinksController } from './bulk-payment-links.controller';
import { BulkPaymentLinksService } from './bulk-payment-links.service';
import { RecurringPaymentsController } from './recurring-payments.controller';
import { RecurringPaymentsService } from './recurring-payments.service';
import { RecurringPaymentsScheduler } from './recurring-payments.scheduler';
import { RecurringPaymentsRepository } from './recurring-payments.repository';
import { RecurringPaymentProcessor } from '../stellar/recurring-payment-processor';
import { SupabaseModule } from '../supabase/supabase.module';
import { StellarModule } from '../stellar/stellar.module';
import { ApiKeysModule } from '../api-keys/api-keys.module';

@Module({
  controllers: [LinksController, BulkPaymentLinksController, RecurringPaymentsController],
  providers: [
    LinksService,
    BulkPaymentLinksService,
    RecurringPaymentsService,
    RecurringPaymentsScheduler,
    RecurringPaymentsRepository,
    RecurringPaymentProcessor,
  ],
  exports: [LinksService, RecurringPaymentsService, BulkPaymentLinksService],
  imports: [SupabaseModule, StellarModule, ApiKeysModule],
})
export class LinksModule {}
