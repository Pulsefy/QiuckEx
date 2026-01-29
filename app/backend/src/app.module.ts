import { Module } from '@nestjs/common';
import { EventEmitterModule } from '@nestjs/event-emitter';
import { ThrottlerModule } from '@nestjs/throttler';

import { AppConfigModule } from './config';
import { HealthModule } from './health/health.module';
import { StellarModule } from './stellar/stellar.module';
import { SupabaseModule } from './supabase/supabase.module';
import { UsernamesModule } from './usernames/usernames.module';

@Module({
  imports: [
    AppConfigModule,
    EventEmitterModule.forRoot({
      wildcard: true,
      delimiter: '.',
    }),
    ThrottlerModule.forRoot([{
      ttl: 60000, 
      limit: 20,
    }]),

    AppConfigModule,
    SupabaseModule,
    HealthModule,
    StellarModule,
    UsernamesModule,
  ],
})
export class AppModule {}
