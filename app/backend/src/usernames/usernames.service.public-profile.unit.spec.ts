import { Test, TestingModule } from '@nestjs/testing';
import { UsernamesService } from './usernames.service';
import { SupabaseService } from '../supabase/supabase.service';
import { AppConfigService } from '../config/app-config.service';
import { UsernameValidationError } from './errors';

describe('UsernamesService - Public Profile Discovery', () => {
  let service: UsernamesService;
  let supabaseMock: Partial<SupabaseService>;
  let configMock: Partial<AppConfigService>;

  beforeEach(async () => {
    supabaseMock = {
      searchPublicUsernames: jest.fn(),
      getTrendingCreators: jest.fn(),
      togglePublicProfile: jest.fn(),
      updateUsernameActivity: jest.fn(),
      listUsernamesByPublicKey: jest.fn(),
    };

    configMock = {
      maxUsernamesPerWallet: 5,
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        UsernamesService,
        {
          provide: SupabaseService,
          useValue: supabaseMock,
        },
        {
          provide: AppConfigService,
          useValue: configMock,
        },
      ],
    }).compile();

    service = module.get<UsernamesService>(UsernamesService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('searchPublicUsernames', () => {
    it('should return search results sorted by similarity score', async () => {
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
        {
          id: '2',
          username: 'alicen',
          public_key: 'GCXHJ66KNR5M3C7F8T9A0B1C2D3E4F5G6H7I8J9K0LAS',
          created_at: '2025-02-20T08:00:00Z',
          last_active_at: '2025-03-26T10:00:00Z',
          is_public: true,
          similarity_score: 85,
        },
      ];

      supabaseMock.searchPublicUsernames!.mockResolvedValue(mockResults);

      const results = await service.searchPublicUsernames('alice', 10);

      expect(results).toHaveLength(2);
      expect(results[0].username).toBe('alice');
      expect(results[0].similarity_score).toBe(95);
      expect(supabaseMock.searchPublicUsernames).toHaveBeenCalledWith('alice', 10);
    });

    it('should throw error for query shorter than 2 characters', async () => {
      await expect(service.searchPublicUsernames('a', 10)).rejects.toThrow(
        UsernameValidationError,
      );
      await expect(service.searchPublicUsernames('', 10)).rejects.toThrow(
        UsernameValidationError,
      );
    });

    it('should normalize query before searching', async () => {
      const mockResults = [
        {
          id: '1',
          username: 'alice',
          public_key: 'GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR',
          created_at: '2025-02-19T08:00:00Z',
          last_active_at: '2025-03-27T10:00:00Z',
          is_public: true,
          similarity_score: 90,
        },
      ];

      supabaseMock.searchPublicUsernames!.mockResolvedValue(mockResults);

      await service.searchPublicUsernames('  ALICE  ', 10);

      expect(supabaseMock.searchPublicUsernames).toHaveBeenCalledWith('alice', 10);
    });

    it('should update activity timestamp for top result', async () => {
      const mockResults = [
        {
          id: '1',
          username: 'alice',
          public_key: 'GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR',
          created_at: '2025-02-19T08:00:00Z',
          last_active_at: '2025-03-27T10:00:00Z',
          is_public: true,
          similarity_score: 90,
        },
      ];

      supabaseMock.searchPublicUsernames!.mockResolvedValue(mockResults);
      supabaseMock.updateUsernameActivity!.mockResolvedValue();

      await service.searchPublicUsernames('alice', 10);

      expect(supabaseMock.updateUsernameActivity).toHaveBeenCalledWith('alice');
    });
  });

  describe('getTrendingCreators', () => {
    it('should return trending creators sorted by volume', async () => {
      const mockCreators = [
        {
          id: '1',
          username: 'topcreator',
          public_key: 'GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR',
          created_at: '2025-02-19T08:00:00Z',
          last_active_at: '2025-03-27T10:00:00Z',
          is_public: true,
          transaction_volume: 50000,
          transaction_count: 120,
        },
        {
          id: '2',
          username: 'risingstar',
          public_key: 'GCXHJ66KNR5M3C7F8T9A0B1C2D3E4F5G6H7I8J9K0LAS',
          created_at: '2025-02-20T08:00:00Z',
          last_active_at: '2025-03-26T10:00:00Z',
          is_public: true,
          transaction_volume: 25000,
          transaction_count: 65,
        },
      ];

      supabaseMock.getTrendingCreators!.mockResolvedValue(mockCreators);

      const result = await service.getTrendingCreators(24, 10);

      expect(result).toHaveLength(2);
      expect(result[0].username).toBe('topcreator');
      expect(result[0].transaction_volume).toBe(50000);
      expect(supabaseMock.getTrendingCreators).toHaveBeenCalledWith(24, 10);
    });

    it('should throw error for invalid time window', async () => {
      await expect(service.getTrendingCreators(0, 10)).rejects.toThrow(
        UsernameValidationError,
      );
      await expect(service.getTrendingCreators(1000, 10)).rejects.toThrow(
        UsernameValidationError,
      );
    });

    it('should use default values when not provided', async () => {
      supabaseMock.getTrendingCreators!.mockResolvedValue([]);

      await service.getTrendingCreators();

      expect(supabaseMock.getTrendingCreators).toHaveBeenCalledWith(24, 10);
    });
  });

  describe('togglePublicProfile', () => {
    it('should toggle public profile visibility successfully', async () => {
      const existingUsernames = [
        {
          id: '1',
          username: 'alice',
          public_key: 'GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR',
          created_at: '2025-02-19T08:00:00Z',
        },
      ];

      supabaseMock.listUsernamesByPublicKey!.mockResolvedValue(existingUsernames);
      supabaseMock.togglePublicProfile!.mockResolvedValue();

      await expect(
        service.togglePublicProfile('alice', 'GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR', true),
      ).resolves.toBeUndefined();

      expect(supabaseMock.togglePublicProfile).toHaveBeenCalledWith('alice', true);
    });

    it('should normalize username before toggling', async () => {
      const existingUsernames = [
        {
          id: '1',
          username: 'alice',
          public_key: 'GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR',
          created_at: '2025-02-19T08:00:00Z',
        },
      ];

      supabaseMock.listUsernamesByPublicKey!.mockResolvedValue(existingUsernames);
      supabaseMock.togglePublicProfile!.mockResolvedValue();

      await service.togglePublicProfile('  ALICE  ', 'GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR', false);

      expect(supabaseMock.togglePublicProfile).toHaveBeenCalledWith('alice', false);
    });

    it('should throw error if username not found', async () => {
      supabaseMock.listUsernamesByPublicKey!.mockResolvedValue([]);

      await expect(
        service.togglePublicProfile('nonexistent', 'GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR', true),
      ).rejects.toThrow(UsernameValidationError);

      await expect(
        service.togglePublicProfile('nonexistent', 'GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR', true),
      ).rejects.toThrowError('Username not found or does not belong to this wallet');
    });

    it('should throw error if username belongs to different wallet', async () => {
      const existingUsernames = [
        {
          id: '1',
          username: 'alice',
          public_key: 'GCXHJ66KNR5M3C7F8T9A0B1C2D3E4F5G6H7I8J9K0LAS',
          created_at: '2025-02-19T08:00:00Z',
        },
      ];

      supabaseMock.listUsernamesByPublicKey!.mockResolvedValue(existingUsernames);

      await expect(
        service.togglePublicProfile('alice', 'GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR', true),
      ).rejects.toThrow(UsernameValidationError);
    });
  });
});
