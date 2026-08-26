import { Module } from "@nestjs/common";

import { SupabaseModule } from "../supabase/supabase.module";
import { UsernamesController } from "./usernames.controller";
import { UsernamesService } from "./usernames.service";
import { DiscoveryCacheService } from "./cache/discovery-cache.service";
import {
  SupabaseUsernamesRepository,
  USERNAMES_REPOSITORY,
} from "./usernames.repository";

@Module({
  imports: [SupabaseModule],
  controllers: [UsernamesController],
  providers: [
    UsernamesService,
    DiscoveryCacheService,
    {
      provide: USERNAMES_REPOSITORY,
      useClass: SupabaseUsernamesRepository,
    },
  ],
  exports: [UsernamesService],
})
export class UsernamesModule {}
