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
    };

    configMock = { maxUsernamesPerWallet: 5 };

    discoveryCacheMock = {
      getSearchResults: jest.fn(),
      setSearchResults: jest.fn(),
      getTrendingResults: jest.fn(),
      setTrendingResults: jest.fn(),
      getRecentlyActiveResults: jest.fn(),
      setRecentlyActiveResults: jest.fn(),
      invalidateSearchCache: jest.fn(),
      invalidateTrendingCache: jest.fn(),
      invalidateRecentlyActiveCache: jest.fn(),
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
      expect(res).toHaveLength(2);
      expect(res[0].username).toBe('alice');
      expect(supabaseMock.updateUsernameActivity).toHaveBeenCalledWith('alice');
    });

    it('throws for short queries', async () => {
      await expect(service.searchPublicUsernames('a', 10)).rejects.toThrow(UsernameValidationError);
      await expect(service.searchPublicUsernames('', 10)).rejects.toThrow(UsernameValidationError);
    });
  });

  describe('getTrendingCreators', () => {
    it('returns trending creators', async () => {
      supabaseMock.getTrendingCreators!.mockResolvedValue([]);
      await service.getTrendingCreators();
      expect(supabaseMock.getTrendingCreators).toHaveBeenCalledWith(24, 10);
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
});