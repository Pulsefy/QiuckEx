import { BadRequestException, Body, Controller, Delete, Get, HttpCode, HttpStatus, Param, Patch, Post, Req, UseGuards } from '@nestjs/common';
import { ApiCreatedResponse, ApiOkResponse, ApiOperation, ApiTags } from '@nestjs/swagger';
import { Request } from 'express';
import { ApiKeyGuard } from '../auth/guards/api-key.guard';
import { RequireApiKey } from '../auth/decorators/require-api-key.decorator';
import { RequireScopes } from '../auth/decorators/require-scopes.decorator';
import { InviteTeamMemberDto } from './dto/invite-team-member.dto';
import { UpdateTeamRoleDto } from './dto/update-team-role.dto';
import { ListTeamsResponseDto, RemoveTeamMemberResponseDto, TeamMemberResponseDto } from './dto/teams-response.dto';
import { TeamsService } from './teams.service';

@ApiTags('teams')
@Controller('teams')
@UseGuards(ApiKeyGuard)
@RequireApiKey()
export class TeamsController {
  constructor(private readonly service: TeamsService) {}

  @Get()
  @ApiOperation({ summary: 'List team members for the organization' })
  @ApiOkResponse({
    description: 'List of team members and caller role',
    type: ListTeamsResponseDto,
  })
  async list(@Req() req: Request): Promise<ListTeamsResponseDto> {
    const organizationId = this.organizationId(req);
    return {
      members: await this.service.list(organizationId),
      currentRole: req.organizationContext?.role ?? 'read_only',
    };
  }

  @Post('invite')
  @RequireScopes('admin')
  @ApiOperation({ summary: 'Invite a new team member' })
  @ApiCreatedResponse({
    description: 'The invited team member details',
    type: TeamMemberResponseDto,
  })
  invite(@Req() req: Request, @Body() dto: InviteTeamMemberDto): Promise<TeamMemberResponseDto> {
    return this.service.invite(this.organizationId(req), req.apiKey?.id ?? 'unknown', dto);
  }

  @Patch(':id/role')
  @RequireScopes('admin')
  @ApiOperation({ summary: 'Update a team member role' })
  @ApiOkResponse({
    description: 'The updated team member details',
    type: TeamMemberResponseDto,
  })
  updateRole(@Req() req: Request, @Param('id') id: string, @Body() dto: UpdateTeamRoleDto): Promise<TeamMemberResponseDto> {
    return this.service.updateRole(this.organizationId(req), id, dto);
  }

  @Delete(':id')
  @RequireScopes('admin')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Remove a team member' })
  @ApiOkResponse({
    description: 'Removal success confirmation',
    type: RemoveTeamMemberResponseDto,
  })
  async remove(@Req() req: Request, @Param('id') id: string): Promise<RemoveTeamMemberResponseDto> {
    await this.service.remove(this.organizationId(req), id);
    return { success: true };
  }

  private organizationId(req: Request): string {
    const organizationId = req.organizationContext?.organizationId;
    if (!organizationId) throw new BadRequestException('An organization-scoped API key is required');
    return organizationId;
  }
}

