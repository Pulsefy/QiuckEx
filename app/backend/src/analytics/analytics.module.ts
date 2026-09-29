import { Module } from '@nestjs/common';
import { ApiKeysModule } from '../api-keys/api-keys.module';
import { SupabaseModule } from '../supabase/supabase.module';
import { AnalyticsController } from './analytics.controller';
import { AnalyticsService } from './analytics.service';
import { SchemaRegistryService } from './schema-registry.service';

@Module({
  imports: [SupabaseModule, ApiKeysModule],
  controllers: [AnalyticsController],
  providers: [AnalyticsService, SchemaRegistryService],
  exports: [AnalyticsService, SchemaRegistryService],
})
export class AnalyticsModule {}

