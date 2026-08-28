import { Module } from '@nestjs/common';
import { ApiKeysModule } from '../api-keys/api-keys.module';
import { SupabaseModule } from '../supabase/supabase.module';
import { AnalyticsController } from './analytics.controller';
import { AnalyticsService } from './analytics.service';
import { AnalyticsEventsService } from './analytics-events.service';
import { AnalyticsStaleCache } from './analytics-stale-cache';

@Module({
  imports: [SupabaseModule, ApiKeysModule],
  controllers: [AnalyticsController],
  providers: [AnalyticsService, AnalyticsEventsService, AnalyticsStaleCache],
  exports: [AnalyticsService],
})
export class AnalyticsModule {}

