import { Module } from '@nestjs/common';

import { stellarConfig } from './config/stellar.config';
import { HealthModule } from './health/health.module';
import { StellarModule } from './stellar/stellar.module';
import { SupabaseModule } from './supabase/supabase.module';
import { UsernamesModule } from './usernames/usernames.module';

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
