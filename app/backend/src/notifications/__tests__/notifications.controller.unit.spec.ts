import { BadRequestException } from '@nestjs/common';
import { NotificationsController } from '../notifications.controller';
import { InAppNotificationRepository } from '../in-app-notification.repository';

describe('NotificationsController read sync', () => {
  const inAppRepo = {
    findByUser: jest.fn(),
    markAsRead: jest.fn(),
    markAllAsRead: jest.fn(),
  };

  const controller = new NotificationsController(
    inAppRepo as unknown as InAppNotificationRepository,
  );

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('lists in-app notifications using query publicKey', async () => {
    inAppRepo.findByUser.mockResolvedValue({ data: [] });

    await controller.getInApp({}, 2, 10, 'GPUBLIC');

    expect(inAppRepo.findByUser).toHaveBeenCalledWith('GPUBLIC', 2, 10);
  });

  it('lists in-app notifications using authenticated user when present', async () => {
    inAppRepo.findByUser.mockResolvedValue({ data: [] });

    await controller.getInApp({ user: { publicKey: 'GAUTH' } }, 1, 20);

    expect(inAppRepo.findByUser).toHaveBeenCalledWith('GAUTH', 1, 20);
  });

  it('marks a single notification as read', async () => {
    inAppRepo.markAsRead.mockResolvedValue({ data: null });

    await controller.markRead('notif-1');

    expect(inAppRepo.markAsRead).toHaveBeenCalledWith('notif-1');
  });

  it('marks all notifications as read for publicKey', async () => {
    inAppRepo.markAllAsRead.mockResolvedValue({ data: null });

    await controller.markAll({}, 'GPUBLIC');

    expect(inAppRepo.markAllAsRead).toHaveBeenCalledWith('GPUBLIC');
  });

  it('rejects mark-all when publicKey is missing', () => {
    expect(() => controller.markAll({})).toThrow(BadRequestException);
  });
});
