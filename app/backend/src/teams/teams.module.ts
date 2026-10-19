import { Module } from '@nestjs/common';
import { SupabaseModule } from '../supabase/supabase.module';
import { NotificationsModule } from '../notifications/notifications.module';
import { TeamsController } from './teams.controller';
import { TeamInvitationsController } from './team-invitations.controller';
import { TeamsRepository } from './teams.repository';
import { TeamsService } from './teams.service';

@Module({
  imports: [SupabaseModule, NotificationsModule],
  controllers: [TeamsController, TeamInvitationsController],
  providers: [TeamsRepository, TeamsService],
})
export class TeamsModule {}
