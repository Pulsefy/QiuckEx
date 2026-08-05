import { Test, TestingModule } from '@nestjs/testing';
import { ConflictException, ForbiddenException } from '@nestjs/common';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { UsernamesController } from './usernames.controller';
import { UsernamesService } from './usernames.service';
import {
  UsernameConflictError,
  UsernameLimitExceededError,
} from './errors';

describe('UsernamesController', () => {
  let controller: UsernamesController;
  let usernamesService: jest.Mocked<UsernamesService>;
  let eventEmitter: jest.Mocked<EventEmitter2>;

  const validPublicKey = 'GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR';

  beforeEach(async () => {
    const mockCreate = jest.fn().mockResolvedValue({ ok: true });
    const mockListByPublicKey = jest.fn().mockResolvedValue([]);
    const mockGetTrendingCreators = jest.fn().mockResolvedValue({ data: [], next_cursor: null, has_more: false });
    const mockGetRecentlyActiveUsers = jest.fn().mockResolvedValue({ data: [], next_cursor: null, has_more: false });
    const mockGetFeaturedCreators = jest.fn().mockResolvedValue({ data: [], next_cursor: null, has_more: false });
    const mockEmit = jest.fn();

    const module: TestingModule = await Test.createTestingModule({
      controllers: [UsernamesController],
      providers: [
        {
          provide: UsernamesService,
          useValue: {
            create: mockCreate,
            listByPublicKey: mockListByPublicKey,
            getTrendingCreators: mockGetTrendingCreators,
            getRecentlyActiveUsers: mockGetRecentlyActiveUsers,
            getFeaturedCreators: mockGetFeaturedCreators,
          },
        },
        {
          provide: EventEmitter2,
          useValue: { emit: mockEmit },
        },
      ],
    }).compile();

    controller = module.get<UsernamesController>(UsernamesController);
    usernamesService = module.get(UsernamesService) as jest.Mocked<UsernamesService>;
    eventEmitter = module.get(EventEmitter2) as jest.Mocked<EventEmitter2>;
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('createUsername', () => {
    it('returns 201 and ok: true on success', async () => {
      const body = { username: 'alice_123', publicKey: validPublicKey };
      const result = await controller.createUsername(body);
      expect(result).toEqual({ ok: true });
      expect(usernamesService.create).toHaveBeenCalledWith('alice_123', validPublicKey);
      expect(eventEmitter.emit).toHaveBeenCalledWith(
        'username.claimed',
        expect.objectContaining({
          username: 'alice_123',
          publicKey: validPublicKey,
        }),
      );
    });

    it('throws ConflictException when username is already taken', async () => {
      usernamesService.create.mockRejectedValueOnce(
        new UsernameConflictError('taken'),
      );
      const body = { username: 'taken', publicKey: validPublicKey };
      const err = await controller.createUsername(body).catch((e) => e);
      expect(err).toBeInstanceOf(ConflictException);
      expect(err.response).toMatchObject({
        code: 'USERNAME_CONFLICT',
        message: expect.stringContaining('taken'),
      });
    });

    it('throws ForbiddenException when wallet limit exceeded', async () => {
      usernamesService.create.mockRejectedValueOnce(
        new UsernameLimitExceededError(validPublicKey, 2),
      );
      const body = { username: 'newuser', publicKey: validPublicKey };
      const err = await controller.createUsername(body).catch((e) => e);
      expect(err).toBeInstanceOf(ForbiddenException);
      expect(err.response).toMatchObject({ code: 'USERNAME_LIMIT_EXCEEDED' });
    });
  });

  describe('listUsernames', () => {
    it('returns usernames for wallet', async () => {
      const rows = [
        {
          id: 'id1',
          username: 'alice',
          public_key: validPublicKey,
          created_at: '2025-01-01T00:00:00Z',
        },
      ];
      usernamesService.listByPublicKey.mockResolvedValueOnce(rows);
      const result = await controller.listUsernames({ publicKey: validPublicKey });
      expect(result).toEqual({ usernames: rows });
      expect(usernamesService.listByPublicKey).toHaveBeenCalledWith(validPublicKey);
    });
  });

  describe('getTrendingCreators', () => {
    it('maps ranked creators to the response shape and forwards pagination info', async () => {
      const creators = [
        {
          id: 'id-1',
          username: 'alice',
          public_key: validPublicKey,
          created_at: '2025-01-01T00:00:00Z',
          last_active_at: '2025-01-02T00:00:00Z',
          is_public: true,
          transaction_volume: 500,
          transaction_count: 5,
        },
      ];
      usernamesService.getTrendingCreators.mockResolvedValueOnce({
        data: creators,
        next_cursor: 'next-page-cursor',
        has_more: true,
      });

      const result = await controller.getTrendingCreators({ timeWindowHours: 24, limit: 10 });

      expect(usernamesService.getTrendingCreators).toHaveBeenCalledWith(24, 10, undefined);
      expect(result.creators).toEqual([
        {
          id: 'id-1',
          username: 'alice',
          publicKey: validPublicKey,
          lastActiveAt: '2025-01-02T00:00:00Z',
          createdAt: '2025-01-01T00:00:00Z',
          transactionVolume: 500,
          transactionCount: 5,
        },
      ]);
      expect(result.timeWindowHours).toBe(24);
      expect(result.next_cursor).toBe('next-page-cursor');
      expect(result.has_more).toBe(true);
    });
  });

  describe('getRecentlyActive', () => {
    it('maps recently active users to the response shape and forwards pagination info', async () => {
      const users = [
        {
          id: 'id-1',
          username: 'alice',
          public_key: validPublicKey,
          created_at: '2025-01-01T00:00:00Z',
          last_active_at: '2025-01-02T00:00:00Z',
          is_public: true,
        },
      ];
      usernamesService.getRecentlyActiveUsers.mockResolvedValueOnce({
        data: users,
        next_cursor: null,
        has_more: false,
      });

      const result = await controller.getRecentlyActive({ timeWindowHours: 24, limit: 10 });

      expect(usernamesService.getRecentlyActiveUsers).toHaveBeenCalledWith(24, 10, undefined);
      expect(result.users).toEqual([
        {
          id: 'id-1',
          username: 'alice',
          publicKey: validPublicKey,
          lastActiveAt: '2025-01-02T00:00:00Z',
          createdAt: '2025-01-01T00:00:00Z',
        },
      ]);
      expect(result.has_more).toBe(false);
      expect(result.next_cursor).toBeNull();
    });
  });

  describe('getFeaturedCreators', () => {
    it('maps featured creators to the response shape and forwards pagination info', async () => {
      const creators = [
        {
          id: 'id-1',
          username: 'alice',
          public_key: validPublicKey,
          created_at: '2025-01-01T00:00:00Z',
          last_active_at: null,
          is_public: true,
          featured_rank: 1,
        },
      ];
      usernamesService.getFeaturedCreators.mockResolvedValueOnce({
        data: creators,
        next_cursor: null,
        has_more: false,
      });

      const result = await controller.getFeaturedCreators({ limit: 10 });

      expect(usernamesService.getFeaturedCreators).toHaveBeenCalledWith(10, undefined);
      expect(result.profiles).toEqual([
        {
          id: 'id-1',
          username: 'alice',
          publicKey: validPublicKey,
          lastActiveAt: '2025-01-01T00:00:00Z',
          createdAt: '2025-01-01T00:00:00Z',
          featuredRank: 1,
        },
      ]);
      expect(result.has_more).toBe(false);
    });
  });
});
