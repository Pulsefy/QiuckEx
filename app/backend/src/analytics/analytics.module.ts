import { Module } from '@nestjs/common';
import { ApiKeysModule } from '../api-keys/api-keys.module';
import { MetricsModule } from '../metrics/metrics.module';
import { SupabaseModule } from '../supabase/supabase.module';
import { AnalyticsController } from './analytics.controller';
import { AnalyticsService } from './analytics.service';
import { AnalyticsEventRegistryService } from './events/analytics-event-registry.service';

@Module({
  imports: [SupabaseModule, ApiKeysModule, MetricsModule],
  controllers: [AnalyticsController],
  providers: [AnalyticsService, AnalyticsEventRegistryService],
  exports: [AnalyticsService, AnalyticsEventRegistryService],
})
export class AnalyticsModule {}

