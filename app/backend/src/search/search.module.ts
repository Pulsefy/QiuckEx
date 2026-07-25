import { Module } from '@nestjs/common';
import { SearchController } from './search.controller';
import { SearchService } from './search.service';
import { UsernamesModule } from '../usernames/usernames.module';
import { MarketplaceModule } from '../marketplace/marketplace.module';
import { SupabaseModule } from '../supabase/supabase.module';

@Module({
  imports: [UsernamesModule, MarketplaceModule, SupabaseModule],
  controllers: [SearchController],
  providers: [SearchService],
  exports: [SearchService],
})
export class SearchModule {}
