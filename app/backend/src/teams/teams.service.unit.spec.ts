import { BadRequestException } from '@nestjs/common';
import { TeamsService } from './teams.service';
import { TeamsRepository } from './teams.repository';
import { NotificationService } from '../notifications/notification.service';

const pendingMember = {
  id: 'member-1',
  name: 'Invitee',
  email: 'invitee@example.com',
  role: 'viewer' as const,
  status: 'pending' as const,
  createdAt: '2026-10-20T00:00:00.000Z',
  updatedAt: '2026-10-20T00:00:00.000Z',
};

describe('TeamsService invitation lifecycle', () => {
  it('sends an invitation code and activates the pending invite when accepted', async () => {
    let member = pendingMember;
    let storedHash: string | undefined;
    const repository = {
      insert: jest.fn(async (_org: string, _by: string, input: { inviteTokenHash: string }) => {
        storedHash = input.inviteTokenHash;
        return member;
      }),
      acceptInvite: jest.fn(async (token: string) => {
        const { createHash } = await import('crypto');
        const hash = createHash('sha256').update(token).digest('hex');
        if (!storedHash || hash !== storedHash || member.status !== 'pending') return null;
        member = { ...member, status: 'active' };
        storedHash = undefined;
        return member;
      }),
    } as unknown as jest.Mocked<TeamsRepository>;
    const notifications = {
      sendTeamInvitationEmail: jest.fn().mockResolvedValue(undefined),
    } as unknown as jest.Mocked<NotificationService>;
    const service = new TeamsService(repository, notifications);

    await service.invite('org-1', 'admin-key', {
      name: 'Invitee',
      email: 'invitee@example.com',
    });

    expect(member.status).toBe('pending');
    expect(notifications.sendTeamInvitationEmail).toHaveBeenCalledWith(
      expect.objectContaining({
        email: 'invitee@example.com',
        organizationId: 'org-1',
        acceptUrl: expect.stringContaining('/teams/accept-invite'),
      }),
    );
    const { token } = notifications.sendTeamInvitationEmail.mock.calls[0][0];
    expect(storedHash).not.toBe(token);

    const accepted = await service.acceptInvite(token);

    expect(accepted.status).toBe('active');
    expect(repository.acceptInvite).toHaveBeenCalledWith(token);
  });

  it('rejects invalid or expired invitation codes', async () => {
    const repository = {
      acceptInvite: jest.fn().mockResolvedValue(null),
    } as unknown as jest.Mocked<TeamsRepository>;
    const notifications = {
      sendTeamInvitationEmail: jest.fn(),
    } as unknown as jest.Mocked<NotificationService>;
    const service = new TeamsService(repository, notifications);

    await expect(service.acceptInvite('invalid')).rejects.toBeInstanceOf(
      BadRequestException,
    );
  });
});
