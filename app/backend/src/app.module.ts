import { Module } from '@nestjs/common';
import { EventEmitterModule } from '@nestjs/event-emitter';

import { stellarConfig } from './config/stellar.config';
import { HealthModule } from './health/health.module';
import { StellarModule } from './stellar/stellar.module';
import { SupabaseModule } from './supabase/supabase.module';
import { UsernamesModule } from './usernames/usernames.module';
import { NotificationService } from './notifications/notification.service';
import { TransactionsModule } from './transactions/transactions.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: [stellarConfig],
    }),
    SupabaseModule,
    HealthModule,
    StellarModule,
    UsernamesModule,
  ],
})
export class AppModule {}
