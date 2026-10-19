import { BadRequestException, Injectable, NotFoundException } from '@nestjs/common';
import { randomBytes, createHash } from 'crypto';
import { InviteTeamMemberDto } from './dto/invite-team-member.dto';
import { UpdateTeamRoleDto } from './dto/update-team-role.dto';
import { TeamMember } from './teams.model';
import { TeamsRepository } from './teams.repository';
import { NotificationService } from '../notifications/notification.service';

const INVITE_TTL_MS = 7 * 24 * 60 * 60 * 1000;

@Injectable()
export class TeamsService {
  constructor(
    private readonly repository: TeamsRepository,
    private readonly notifications: NotificationService,
  ) {}

  list(organizationId: string): Promise<TeamMember[]> {
    return this.repository.list(organizationId);
  }

  async invite(organizationId: string, invitedBy: string, dto: InviteTeamMemberDto): Promise<TeamMember> {
    const token = randomBytes(32).toString('base64url');
    const inviteExpiresAt = new Date(Date.now() + INVITE_TTL_MS).toISOString();
    const member = await this.repository.insert(organizationId, invitedBy, {
      name: dto.name,
      email: dto.email,
      role: dto.role ?? 'viewer',
      inviteTokenHash: createHash('sha256').update(token).digest('hex'),
      inviteExpiresAt,
    });

    const apiBaseUrl = process.env.API_BASE_URL ?? process.env.APP_URL ??
      `http://localhost:${process.env.PORT ?? '4000'}`;
    const acceptUrl = new URL('/teams/accept-invite', apiBaseUrl);
    await this.notifications.sendTeamInvitationEmail({
      email: member.email,
      organizationId,
      acceptUrl: acceptUrl.toString(),
      token,
    });
    return member;
  }

  async acceptInvite(token: string): Promise<TeamMember> {
    const member = await this.repository.acceptInvite(token);
    if (!member) throw new BadRequestException('Invitation code is invalid, expired, or already used');
    return member;
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
