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
      searchActiveListings: jest.fn(),
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

  describe('searchDiscovery', () => {
    it('returns a mixed shared-result payload for profiles and listings', async () => {
      supabaseMock.searchPublicUsernames!.mockResolvedValue([
        { id: '1', username: 'alice', public_key: 'pk1', created_at: '2024-01-01', last_active_at: '2024-01-02', is_public: true, similarity_score: 95 },
      ]);
      supabaseMock.searchActiveListings!.mockResolvedValue({
        listings: [
          { id: 'listing-1', username: 'alice', seller_public_key: 'pk2', asking_price: 250, status: 'active', created_at: '2024-01-03', updated_at: '2024-01-03', sold_at: null, buyer_public_key: null, final_price: null },
        ],
        total: 1,
        next_cursor: null,
        has_more: false,
      });

      const res = await service.searchDiscovery('alice', 10);

      expect(res.results).toHaveLength(2);
      expect(res.results[0]).toEqual(expect.objectContaining({ kind: 'profile', username: 'alice' }));
      expect(res.results[1]).toEqual(expect.objectContaining({ kind: 'listing', username: 'alice' }));
      expect(res.total).toBe(2);
      expect(res.empty).toBe(false);
      expect(res.next_cursor).toBeNull();
    });

    it('returns an empty-state payload for blank queries', async () => {
      const res = await service.searchDiscovery('   ', 10);

      expect(res.results).toEqual([]);
      expect(res.total).toBe(0);
      expect(res.empty).toBe(true);
      expect(res.has_more).toBe(false);
      expect(supabaseMock.searchPublicUsernames).not.toHaveBeenCalled();
      expect(supabaseMock.searchActiveListings).not.toHaveBeenCalled();
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
});