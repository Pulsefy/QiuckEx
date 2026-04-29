import { Module } from "@nestjs/common";

import { SupabaseModule } from "../supabase/supabase.module";
import { UsernamesController } from "./usernames.controller";
import { UsernamesService } from "./usernames.service";
import { DiscoveryCacheService } from "./cache/discovery-cache.service";

@Module({
  imports: [SupabaseModule],
  controllers: [UsernamesController],
  providers: [UsernamesService, DiscoveryCacheService],
  exports: [UsernamesService],
})
export class UsernamesModule {}
