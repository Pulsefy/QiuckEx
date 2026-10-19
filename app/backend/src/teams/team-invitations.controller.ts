import { Body, Controller, Post } from '@nestjs/common';
import { IsNotEmpty, IsString, MaxLength } from 'class-validator';
import { RateLimitTier } from '../auth/decorators/rate-limit-group.decorator';
import { TeamsService } from './teams.service';

class AcceptTeamInvitationDto {
  @IsString()
  @IsNotEmpty()
  @MaxLength(128)
  token: string;
}

@Controller('teams')
export class TeamInvitationsController {
  constructor(private readonly service: TeamsService) {}

  @Post('accept-invite')
  @RateLimitTier('mutation')
  acceptInvite(@Body() dto: AcceptTeamInvitationDto) {
    return this.service.acceptInvite(dto.token);
  }
}