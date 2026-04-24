import { Test, TestingModule } from '@nestjs/testing';
import { BadRequestException, NotFoundException } from '@nestjs/common';
import { UsernamesController } from './usernames.controller';
import { UsernamesService } from './usernames.service';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { UsernameValidationError, UsernameErrorCode } from './errors';

describe('UsernamesController - Public Profile Discovery (Integration)', () => {
  let controller: UsernamesController;
  let serviceMock: {
    searchPublicUsernames: jest.Mock;
    getTrendingCreators: jest.Mock;
    togglePublicProfile: jest.Mock;
    listByPublicKey: jest.Mock;
    create: jest.Mock;
  };
  let eventEmitterMock: Partial<EventEmitter2>;

  beforeEach(async () => {
    serviceMock = {
      searchPublicUsernames: jest.fn(),
      getTrendingCreators: jest.fn(),
      togglePublicProfile: jest.fn(),
      listByPublicKey: jest.fn(),
      create: jest.fn(),
    };

    eventEmitterMock = {
      emit: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [UsernamesController],
      providers: [
        {
          provide: UsernamesService,
          useValue: serviceMock,
        },
        {
          provide: EventEmitter2,
          useValue: eventEmitterMock,
        },
      ],
    }).compile();

    controller = module.get<UsernamesController>(UsernamesController);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('GET /username/search', () => {
    it('should return search results with similarity scores', async () => {
      const mockResults = [
        {
          id: '1',
          username: 'alice',
          public_key: 'GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR',
          created_at: '2025-02-19T08:00:00Z',
          last_active_at: '2025-03-27T10:00:00Z',
          is_public: true,
          similarity_score: 95,
        },
      ];

      serviceMock.searchPublicUsernames.mockResolvedValue(mockResults);

      const result = await controller.searchUsernames({
        query: 'alice',
        limit: 10,
      });

      expect(result.profiles).toHaveLength(1);
      expect(result.profiles[0].username).toBe('alice');
      expect(result.profiles[0].similarityScore).toBe(95);
      expect(result.total).toBe(1);
    });

    it('should map database fields to DTO correctly', async () => {
      const mockResults = [
        {
          id: '1',
          username: 'bob',
          public_key: 'GCXHJ66KNR5M3C7F8T9A0B1C2D3E4F5G6H7I8J9K0LAS',
          created_at: '2025-02-20T08:00:00Z',
          last_active_at: '2025-03-26T10:00:00Z',
          is_public: true,
          similarity_score: 80,
        },
      ];

      serviceMock.searchPublicUsernames.mockResolvedValue(mockResults);

      const result = await controller.searchUsernames({
        query: 'bob',
        limit: 5,
      });

      expect(result.profiles[0]).toEqual({
        id: '1',
        username: 'bob',
        publicKey: 'GCXHJ66KNR5M3C7F8T9A0B1C2D3E4F5G6H7I8J9K0LAS',
        lastActiveAt: '2025-03-26T10:00:00Z',
        createdAt: '2025-02-20T08:00:00Z',
        similarityScore: 80,
      });
    });
  });

  describe('GET /username/trending', () => {
    it('should return trending creators sorted by volume', async () => {
      const mockCreators = [
        {
          id: '1',
          username: 'toptrader',
          public_key: 'GDXYZ123ABC456DEF789GHI012JKL345MNO678PQR901STU',
          created_at: '2025-02-19T08:00:00Z',
          last_active_at: '2025-03-27T10:00:00Z',
          is_public: true,
          transaction_volume: 75000,
          transaction_count: 200,
        },
        {
          id: '2',
          username: 'activeuser',
          public_key: 'GEABC456DEF789GHI012JKL345MNO678PQR901STU234VWX',
          created_at: '2025-02-20T08:00:00Z',
          last_active_at: '2025-03-26T10:00:00Z',
          is_public: true,
          transaction_volume: 35000,
          transaction_count: 95,
        },
      ];

      serviceMock.getTrendingCreators.mockResolvedValue(mockCreators);

      const result = await controller.getTrendingCreators({
        timeWindowHours: 24,
        limit: 10,
      });

      expect(result.creators).toHaveLength(2);
      expect(result.creators[0].username).toBe('toptrader');
      expect(result.creators[0].transactionVolume).toBe(75000);
      expect(result.creators[0].transactionCount).toBe(200);
      expect(result.timeWindowHours).toBe(24);
      expect(result.calculatedAt).toBeDefined();
    });

    it('should map trending data to DTO correctly', async () => {
      const mockCreators = [
        {
          id: '2',
          username: 'creator',
          public_key: 'GFCREATOR123ABC456DEF789GHI012JKL345MNO678PQR901',
          created_at: '2025-02-21T08:00:00Z',
          last_active_at: null,
          is_public: true,
          transaction_volume: 10000,
          transaction_count: 25,
        },
      ];

      serviceMock.getTrendingCreators.mockResolvedValue(mockCreators);

      const result = await controller.getTrendingCreators({
        timeWindowHours: 48,
        limit: 5,
      });

      // When last_active_at is null, should fall back to created_at
      expect(result.creators[0].lastActiveAt).toBe('2025-02-21T08:00:00Z');
      expect(result.creators[0].transactionVolume).toBe(10000);
    });
  });

  describe('POST /username/toggle-public', () => {
    it('should toggle public profile successfully', async () => {
      serviceMock.togglePublicProfile.mockResolvedValue(undefined);

      const result = await controller.togglePublicProfile({
        username: 'alice',
        publicKey: 'GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR',
        isPublic: true,
      });

      expect(result.ok).toBe(true);
      expect(serviceMock.togglePublicProfile).toHaveBeenCalledWith(
        'alice',
        'GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR',
        true,
      );
    });

    it('should handle username not found error', async () => {
      const error = new UsernameValidationError(
        UsernameErrorCode.NOT_FOUND,
        'Username not found or does not belong to this wallet',
        'username',
      );

      serviceMock.togglePublicProfile.mockRejectedValue(error);

      await expect(
        controller.togglePublicProfile({
          username: 'nonexistent',
          publicKey: 'GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR',
          isPublic: true,
        }),
      ).rejects.toThrow(NotFoundException);
    });

    it('should handle validation error', async () => {
      const error = new UsernameValidationError(
        UsernameErrorCode.INVALID_FORMAT,
        'Invalid username format',
        'username',
      );

      serviceMock.togglePublicProfile.mockRejectedValue(error);

      await expect(
        controller.togglePublicProfile({
          username: 'INVALID',
          publicKey: 'GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR',
          isPublic: true,
        }),
      ).rejects.toThrow(BadRequestException);
    });
  });
});
