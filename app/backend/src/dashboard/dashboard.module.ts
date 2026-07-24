import { Module } from '@nestjs/common';
import { SupabaseModule } from '../supabase/supabase.module';
import { DashboardController } from './dashboard.controller';
import { DashboardService } from './dashboard.service';

/**
 * Dashboard activity feed module.
 *
 * Aggregates activity from payments, refunds, notifications,
 * contract actions, username claims, and webhook deliveries
 * into a single cursor-paginated feed endpoint.
 */
@Module({
  imports: [SupabaseModule],
  controllers: [DashboardController],
  providers: [DashboardService],
  exports: [DashboardService],
})
export class DashboardModule {}
