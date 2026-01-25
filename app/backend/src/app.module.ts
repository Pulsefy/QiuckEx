import { Module } from '@nestjs/common';

import { AppConfigModule } from './config';
import { HealthModule } from './health/health.module';
import { SupabaseModule } from './supabase/supabase.module';
import { UsernamesModule } from './usernames/usernames.module';

@Module({
  imports: [AppConfigModule, SupabaseModule, HealthModule, UsernamesModule],
})
export class AppModule {}
