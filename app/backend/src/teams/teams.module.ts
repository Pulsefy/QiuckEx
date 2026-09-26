import { Module } from '@nestjs/common';
import { SupabaseModule } from '../supabase/supabase.module';
import { TeamsController } from './teams.controller';
import { TeamsRepository } from './teams.repository';
import { TeamsService } from './teams.service';

@Module({
  imports: [SupabaseModule],
  controllers: [TeamsController],
  providers: [TeamsRepository, TeamsService],
})
export class TeamsModule {}
