import { Module } from "@nestjs/common";

import { SupabaseModule } from "../supabase/supabase.module";
import { FeatureFlagsModule } from "../feature-flags/feature-flags.module";
import { UsernamesController } from "./usernames.controller";
import { UsernamesService } from "./usernames.service";
import { DiscoveryCacheService } from "./cache/discovery-cache.service";
import { UsernameRankingService } from "./username-ranking.service";

@Module({
  imports: [SupabaseModule, FeatureFlagsModule],
  controllers: [UsernamesController],
  providers: [UsernamesService, DiscoveryCacheService, UsernameRankingService],
  exports: [UsernamesService, UsernameRankingService],
})
export class UsernamesModule {}
