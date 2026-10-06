import { Injectable, NotFoundException } from '@nestjs/common';
import { InviteTeamMemberDto } from './dto/invite-team-member.dto';
import { UpdateTeamRoleDto } from './dto/update-team-role.dto';
import { TeamMember } from './teams.model';
import { TeamsRepository } from './teams.repository';

@Injectable()
export class TeamsService {
  constructor(private readonly repository: TeamsRepository) {}

  list(organizationId: string): Promise<TeamMember[]> {
    return this.repository.list(organizationId);
  }

  invite(organizationId: string, invitedBy: string, dto: InviteTeamMemberDto): Promise<TeamMember> {
    return this.repository.insert(organizationId, invitedBy, {
      name: dto.name,
      email: dto.email,
      role: dto.role ?? 'viewer',
    });
  }

  async updateRole(organizationId: string, id: string, dto: UpdateTeamRoleDto): Promise<TeamMember> {
    try {
      return await this.repository.updateRole(organizationId, id, dto.role);
    } catch (error) {
      if (error instanceof Error && error.message.includes('0 rows')) {
        throw new NotFoundException('Team member not found');
      }
      throw error;
    }
  }

  remove(organizationId: string, id: string): Promise<void> {
    return this.repository.remove(organizationId, id);
  }
}
