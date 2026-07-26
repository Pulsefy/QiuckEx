import { Test, TestingModule } from '@nestjs/testing';
import { UsernamesService } from './usernames.service';
import { SupabaseService } from '../supabase/supabase.service';
import { AppConfigService } from '../config/app-config.service';
import { DiscoveryCacheService } from './cache/discovery-cache.service';
import { UsernameValidationError } from './errors';

describe('UsernamesService - Public Profile Discovery', () => {
  let service: UsernamesService;
  let supabaseMock: jest.Mocked<Partial<SupabaseService>>;
  let configMock: Partial<AppConfigService>;
  let discoveryCacheMock: jest.Mocked<Partial<DiscoveryCacheService>>;

  beforeEach(async () => {
    supabaseMock = {
      searchPublicUsernames: jest.fn(),
      getTrendingCreators: jest.fn(),
      togglePublicProfile: jest.fn(),
      updateUsernameActivity: jest.fn(),
      listUsernamesByPublicKey: jest.fn(),
      getPublicProfile: jest.fn(),
    };

    configMock = { maxUsernamesPerWallet: 5 };

    discoveryCacheMock = {
      getSearchResults: jest.fn(),
      setSearchResults: jest.fn(),
      getTrendingResults: jest.fn(),
      setTrendingResults: jest.fn(),
      getRecentlyActiveResults: jest.fn(),
      setRecentlyActiveResults: jest.fn(),
      getProfile: jest.fn(),
      setProfile: jest.fn(),
      invalidateSearchCache: jest.fn(),
      invalidateTrendingCache: jest.fn(),
      invalidateRecentlyActiveCache: jest.fn(),
      invalidateProfile: jest.fn(),
      invalidateForUsername: jest.fn(),
      getStats: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        UsernamesService,
        { provide: SupabaseService, useValue: supabaseMock },
        { provide: AppConfigService, useValue: configMock },
        { provide: DiscoveryCacheService, useValue: discoveryCacheMock },
      ],
    }).compile();

    service = module.get<UsernamesService>(UsernamesService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('searchPublicUsernames', () => {
    it('returns search results', async () => {
      const mockResults = [
        { id: '1', username: 'alice', public_key: 'pk1', created_at: '', last_active_at: '', is_public: true, similarity_score: 95 },
        { id: '2', username: 'alicen', public_key: 'pk2', created_at: '', last_active_at: '', is_public: true, similarity_score: 85 },
      ];

      supabaseMock.searchPublicUsernames!.mockResolvedValue(mockResults);
      supabaseMock.updateUsernameActivity!.mockResolvedValue(undefined);

      const res = await service.searchPublicUsernames('alice', 10);
      expect(res.data).toHaveLength(2);
      expect(res.data[0].username).toBe('alice');
      expect(supabaseMock.updateUsernameActivity).toHaveBeenCalledWith('alice');
      expect(supabaseMock.searchPublicUsernames).toHaveBeenCalledWith('alice', 11);
    });

    it('throws for short queries', async () => {
      await expect(service.searchPublicUsernames('a', 10)).rejects.toThrow(UsernameValidationError);
      await expect(service.searchPublicUsernames('', 10)).rejects.toThrow(UsernameValidationError);
    });
  });

  describe('getTrendingCreators', () => {
    it('returns trending creators', async () => {
      supabaseMock.getTrendingCreators!.mockResolvedValue([]);
      await service.getTrendingCreators(24, 10);
      expect(supabaseMock.getTrendingCreators).toHaveBeenCalledWith(24, 11);
    });

    it('throws on invalid time window', async () => {
      await expect(service.getTrendingCreators(0)).rejects.toThrow(UsernameValidationError);
      await expect(service.getTrendingCreators(1000)).rejects.toThrow(UsernameValidationError);
    });
  });

  describe('togglePublicProfile', () => {
    it('toggles successfully', async () => {
      supabaseMock.listUsernamesByPublicKey!.mockResolvedValue([{ id: '1', username: 'alice', public_key: 'pk1', created_at: '' }]);
      supabaseMock.togglePublicProfile!.mockResolvedValue();

      await expect(service.togglePublicProfile('alice', 'pk1', true)).resolves.toBeUndefined();
      expect(supabaseMock.togglePublicProfile).toHaveBeenCalledWith('alice', true);
    });

    it('throws if username not found', async () => {
      supabaseMock.listUsernamesByPublicKey!.mockResolvedValue([]);
      await expect(service.togglePublicProfile('alice', 'pk1', true)).rejects.toThrow(UsernameValidationError);
    });
  });

  describe('getPublicProfile', () => {
    it('returns public profile metadata and payment settings when is_public is true', async () => {
      const mockProfile = {
        id: 'uuid-1',
        username: 'alice',
        public_key: 'GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR',
        created_at: '2025-02-19T08:00:00Z',
        last_active_at: '2025-03-27T10:00:00Z',
        is_public: true,
      };

      supabaseMock.getPublicProfile!.mockResolvedValue(mockProfile);

      const result = await service.getPublicProfile('alice');

      expect(result.username).toBe('alice');
      expect(result.public_key).toBe('GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR');
      expect(result.is_public).toBe(true);
      expect(result.paymentSettings).toEqual({
        acceptedAssets: ['USDC', 'XLM', 'AQUA', 'yXLM'],
        defaultAsset: 'USDC',
      });
      expect(discoveryCacheMock.setProfile).toHaveBeenCalledWith('alice', mockProfile);
    });

    it('strips leading @ sign from username parameter', async () => {
      const mockProfile = {
        id: 'uuid-1',
        username: 'alice',
        public_key: 'GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR',
        created_at: '2025-02-19T08:00:00Z',
        last_active_at: '2025-03-27T10:00:00Z',
        is_public: true,
      };

      supabaseMock.getPublicProfile!.mockResolvedValue(mockProfile);

      const result = await service.getPublicProfile('@alice');
      expect(result.username).toBe('alice');
      expect(supabaseMock.getPublicProfile).toHaveBeenCalledWith('alice');
    });

    it('throws PRIVACY_DISABLED when is_public is false', async () => {
      const mockPrivateProfile = {
        id: 'uuid-2',
        username: 'bob',
        public_key: 'GCXHJ66KNR5M3C7F8T9A0B1C2D3E4F5G6H7I8J9K0LAS',
        created_at: '2025-02-20T08:00:00Z',
        last_active_at: null,
        is_public: false,
      };

      supabaseMock.getPublicProfile!.mockResolvedValue(mockPrivateProfile);

      try {
        await service.getPublicProfile('bob');
        fail('Should have thrown UsernameValidationError');
      } catch (err: any) {
        expect(err).toBeInstanceOf(UsernameValidationError);
        expect(err.code).toBe('USERNAME_PRIVACY_DISABLED');
      }
    });

    it('throws NOT_FOUND when username does not exist', async () => {
      supabaseMock.getPublicProfile!.mockResolvedValue(null);

      try {
        await service.getPublicProfile('nonexistent');
        fail('Should have thrown UsernameValidationError');
      } catch (err: any) {
        expect(err).toBeInstanceOf(UsernameValidationError);
        expect(err.code).toBe('USERNAME_NOT_FOUND');
      }
    });
  });
});