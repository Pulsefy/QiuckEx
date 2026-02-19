import { Module } from '@nestjs/common';

import { SupabaseModule } from '../supabase/supabase.module';
import { UsernamesController } from './usernames.controller';
import { UsernamesService } from './usernames.service';

@Module({
  imports: [SupabaseModule],
  controllers: [UsernamesController],
  providers: [UsernamesService],
})
export class UsernamesModule {}
