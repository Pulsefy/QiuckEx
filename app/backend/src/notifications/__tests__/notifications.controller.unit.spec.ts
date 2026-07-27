import { Test, TestingModule } from "@nestjs/testing";
import { NotificationsController } from "../notifications.controller";
import { InAppNotificationRepository } from "../in-app-notification.repository";

describe("NotificationsController", () => {
  let controller: NotificationsController;

  const mockRepo = {
    findByUser: jest.fn(),
    markAsRead: jest.fn(),
    markManyAsRead: jest.fn(),
    markAllAsRead: jest.fn(),
    getUnreadCount: jest.fn(),
  };

  beforeEach(async () => {
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      controllers: [NotificationsController],
      providers: [
        {
          provide: InAppNotificationRepository,
          useValue: mockRepo,
        },
      ],
    }).compile();

    controller = module.get<NotificationsController>(NotificationsController);
  });

  describe("getInApp", () => {
    it("returns notifications for the authenticated user", async () => {
      const req = {
        user: {
          publicKey: "GTEST123",
        },
      };

      const notifications = [
        {
          id: "1",
          title: "Notification",
          read: false,
        },
      ];

      mockRepo.findByUser.mockResolvedValue(notifications);

      const result = await controller.getInApp(req, 1, 20);

      expect(mockRepo.findByUser).toHaveBeenCalledWith("GTEST123", 1, 20);

      expect(result).toEqual(notifications);
    });
  });

  describe("markRead", () => {
    it("marks a notification as read and returns updated unread count", async () => {
      const req = {
        user: {
          publicKey: "GTEST123",
        },
      };

      mockRepo.markAsRead.mockResolvedValue(undefined);
      mockRepo.getUnreadCount.mockResolvedValue(4);

      const result = await controller.markRead(req, "notification-id");

      expect(mockRepo.markAsRead).toHaveBeenCalledWith(
        "GTEST123",
        "notification-id",
      );

      expect(mockRepo.getUnreadCount).toHaveBeenCalledWith("GTEST123");

      expect(result.success).toBe(true);
      expect(result.unreadCount).toBe(4);
      expect(result.syncedAt).toEqual(expect.any(String));
    });
  });

  describe("markManyRead", () => {
    it("marks multiple notifications as read", async () => {
      const req = {
        user: {
          publicKey: "GTEST123",
        },
      };

      mockRepo.markManyAsRead.mockResolvedValue(undefined);
      mockRepo.getUnreadCount.mockResolvedValue(2);

      const body = {
        ids: ["1", "2", "3"],
      };

      const result = await controller.markManyRead(req, body);

      expect(mockRepo.markManyAsRead).toHaveBeenCalledWith("GTEST123", [
        "1",
        "2",
        "3",
      ]);

      expect(mockRepo.getUnreadCount).toHaveBeenCalledWith("GTEST123");

      expect(result.success).toBe(true);
      expect(result.unreadCount).toBe(2);
      expect(result.syncedAt).toEqual(expect.any(String));
    });
  });

  describe("markAll", () => {
    it("marks every notification as read", async () => {
      const req = {
        user: {
          publicKey: "GTEST123",
        },
      };

      mockRepo.markAllAsRead.mockResolvedValue(undefined);
      mockRepo.getUnreadCount.mockResolvedValue(0);

      const result = await controller.markAll(req);

      expect(mockRepo.markAllAsRead).toHaveBeenCalledWith("GTEST123");

      expect(mockRepo.getUnreadCount).toHaveBeenCalledWith("GTEST123");

      expect(result.success).toBe(true);
      expect(result.unreadCount).toBe(0);
      expect(result.syncedAt).toEqual(expect.any(String));
    });
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
