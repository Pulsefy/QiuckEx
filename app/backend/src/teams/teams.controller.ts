import { BadRequestException, Body, Controller, Delete, Get, Param, Patch, Post, Req, UseGuards } from '@nestjs/common';
import { Request } from 'express';
import { ApiKeyGuard } from '../auth/guards/api-key.guard';
import { RequireApiKey } from '../auth/decorators/require-api-key.decorator';
import { RequireScopes } from '../auth/decorators/require-scopes.decorator';
import { InviteTeamMemberDto } from './dto/invite-team-member.dto';
import { UpdateTeamRoleDto } from './dto/update-team-role.dto';
import { TeamsService } from './teams.service';

@Controller('teams')
@UseGuards(ApiKeyGuard)
@RequireApiKey()
export class TeamsController {
  constructor(private readonly service: TeamsService) {}

  @Get()
  async list(@Req() req: Request) {
    const organizationId = this.organizationId(req);
    return {
      members: await this.service.list(organizationId),
      currentRole: req.organizationContext?.role ?? 'read_only',
    };
  }

  @Post('invite')
  @RequireScopes('admin')
  invite(@Req() req: Request, @Body() dto: InviteTeamMemberDto) {
    return this.service.invite(this.organizationId(req), req.apiKey?.id ?? 'unknown', dto);
  }

  @Patch(':id/role')
  @RequireScopes('admin')
  updateRole(@Req() req: Request, @Param('id') id: string, @Body() dto: UpdateTeamRoleDto) {
    return this.service.updateRole(this.organizationId(req), id, dto);
  }

  @Delete(':id')
  @RequireScopes('admin')
  async remove(@Req() req: Request, @Param('id') id: string) {
    await this.service.remove(this.organizationId(req), id);
    return { success: true };
  }

  private organizationId(req: Request): string {
    const organizationId = req.organizationContext?.organizationId;
    if (!organizationId) throw new BadRequestException('An organization-scoped API key is required');
    return organizationId;
  }
}
