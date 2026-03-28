import { Module } from '@nestjs/common';

import { SupabaseModule } from '../supabase/supabase.module';
import { UsernamesModule } from '../usernames/usernames.module';
import { MarketplaceController } from './marketplace.controller';
import { MarketplaceService } from './marketplace.service';

@Module({
  imports: [SupabaseModule, UsernamesModule],
  controllers: [MarketplaceController],
  providers: [MarketplaceService],
})
export class MarketplaceModule {}
