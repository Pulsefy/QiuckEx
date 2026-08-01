import { Module } from '@nestjs/common';
import { DashboardFeedController } from './dashboard-feed.controller';
import { DashboardFeedService } from './dashboard-feed.service';
import { DashboardFeedRepository } from './dashboard-feed.repository';
import { SupabaseModule } from '../supabase/supabase.module';

@Module({
  imports: [SupabaseModule],
  controllers: [DashboardFeedController],
  providers: [DashboardFeedService, DashboardFeedRepository],
  exports: [DashboardFeedService],
})
export class DashboardFeedModule {}
