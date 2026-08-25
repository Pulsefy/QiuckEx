import { Module, forwardRef } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';

import { FiatRampsController } from './fiat-ramps.controller';
import { FiatRampsService } from './fiat-ramps.service';
import { Sep24TransactionRepository } from './sep24-transaction.repository';
import { Sep24PollingService } from './sep24-polling.service';
import { Sep24PollingWorkerService } from './sep24-polling-worker.service';
import { AnchorClientService } from './anchor-client.service';
import { IdempotencyModule } from '../common/idempotency/idempotency.module';
import { SupabaseModule } from '../supabase/supabase.module';
import { MetricsModule } from '../metrics/metrics.module';
import { sep24Config } from '../config/sep24.config';
import { AppConfigModule } from '../config';
import { JobQueueModule } from '../job-queue/job-queue.module';
import { ReconciliationModule } from '../reconciliation/reconciliation.module';

@Module({
  imports: [
    IdempotencyModule,
    SupabaseModule,
    MetricsModule,
    AppConfigModule,
    ConfigModule.forFeature(sep24Config),
    forwardRef(() => JobQueueModule),
    forwardRef(() => ReconciliationModule),
  ],
  controllers: [FiatRampsController],
  providers: [
    FiatRampsService,
    Sep24TransactionRepository,
    AnchorClientService,
    Sep24PollingService,
    Sep24PollingWorkerService,
  ],
  exports: [
    FiatRampsService,
    Sep24TransactionRepository,
    Sep24PollingService,
    AnchorClientService,
  ],
})
export class FiatRampsModule {}
