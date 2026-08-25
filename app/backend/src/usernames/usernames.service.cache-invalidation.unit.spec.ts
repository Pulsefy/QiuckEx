import { Test, TestingModule } from '@nestjs/testing';
import { UsernamesService } from './usernames.service';
import { USERNAMES_REPOSITORY } from './usernames.repository';
import { AppConfigService } from '../config';
import { DiscoveryCacheService } from './cache/discovery-cache.service';
import { UsernameValidationError } from './errors';

describe('UsernamesService - Cache Invalidation', () => {
  let service: UsernamesService;
  let usernamesRepositoryMock: Record<string, jest.Mock>;
  let cacheMock: jest.Mocked<Partial<DiscoveryCacheService>>;
  let configMock: Partial<AppConfigService>;

  beforeEach(async () => {
    usernamesRepositoryMock = {
      searchPublicUsernames: jest.fn(),
      getTrendingCreators: jest.fn(),
      getRecentlyActiveUsers: jest.fn(),
      togglePublicProfile: jest.fn(),
      updateUsernameActivity: jest.fn(),
      listUsernamesByPublicKey: jest.fn(),
      getPublicProfile: jest.fn(),
    };

    cacheMock = {
      getSearchResults: jest.fn().mockReturnValue(undefined),
      setSearchResults: jest.fn(),
      getTrendingResults: jest.fn().mockReturnValue(undefined),
      setTrendingResults: jest.fn(),
      getRecentlyActiveResults: jest.fn().mockReturnValue(undefined),
      setRecentlyActiveResults: jest.fn(),
      getProfile: jest.fn().mockReturnValue(undefined),
      setProfile: jest.fn(),
      invalidateSearchCache: jest.fn(),
      invalidateTrendingCache: jest.fn(),
      invalidateRecentlyActiveCache: jest.fn(),
      invalidateProfile: jest.fn(),
      invalidateForUsername: jest.fn(),
      getStats: jest.fn(),
    };

    configMock = { maxUsernamesPerWallet: 5 };

    usernamesRepositoryMock.updateUsernameActivity!.mockResolvedValue(undefined);

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        UsernamesService,
        { provide: USERNAMES_REPOSITORY, useValue: usernamesRepositoryMock },
        { provide: AppConfigService, useValue: configMock },
        { provide: DiscoveryCacheService, useValue: cacheMock },
      ],
    }).compile();

    service = module.get<UsernamesService>(UsernamesService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('togglePublicProfile invalidation', () => {
    it('calls invalidateForUsername after successful toggle', async () => {
      usernamesRepositoryMock.listUsernamesByPublicKey!.mockResolvedValue([
        { id: '1', username: 'alice', public_key: 'pk1', created_at: '' },
      ]);
      usernamesRepositoryMock.togglePublicProfile!.mockResolvedValue(undefined);

      await service.togglePublicProfile('alice', 'pk1', true);

      expect(cacheMock.invalidateForUsername).toHaveBeenCalledWith('alice');
    });

    it('normalizes username before invalidation', async () => {
      usernamesRepositoryMock.listUsernamesByPublicKey!.mockResolvedValue([
        { id: '1', username: 'alice', public_key: 'pk1', created_at: '' },
      ]);
      usernamesRepositoryMock.togglePublicProfile!.mockResolvedValue(undefined);

      await service.togglePublicProfile('Alice', 'pk1', false);

      expect(cacheMock.invalidateForUsername).toHaveBeenCalledWith('alice');
    });

    it('does not invalidate cache when username not found', async () => {
      usernamesRepositoryMock.listUsernamesByPublicKey!.mockResolvedValue([]);

      await expect(
        service.togglePublicProfile('ghost', 'pk1', true),
      ).rejects.toThrow(UsernameValidationError);

      expect(cacheMock.invalidateForUsername).not.toHaveBeenCalled();
    });

    it('does not call Supabase toggle when username not found', async () => {
      usernamesRepositoryMock.listUsernamesByPublicKey!.mockResolvedValue([]);

      await expect(
        service.togglePublicProfile('ghost', 'pk1', true),
      ).rejects.toThrow();

      expect(usernamesRepositoryMock.togglePublicProfile).not.toHaveBeenCalled();
    });
  });

  describe('getPublicProfile caching', () => {
    const profile = {
      id: 'id-1',
      username: 'alice',
      public_key: 'pk1',
      created_at: '2025-01-01T00:00:00Z',
      last_active_at: null,
      is_public: true,
    };

    it('returns cached profile without hitting Supabase', async () => {
      cacheMock.getProfile!.mockReturnValue(profile);

      const result = await service.getPublicProfile('alice');

      expect(result).toEqual(profile);
      expect(usernamesRepositoryMock.getPublicProfile).not.toHaveBeenCalled();
      expect(cacheMock.setProfile).not.toHaveBeenCalled();
    });

    it('fetches from Supabase and caches on miss', async () => {
      usernamesRepositoryMock.getPublicProfile!.mockResolvedValue(profile);

      const result = await service.getPublicProfile('alice');

      expect(result).toEqual(profile);
      expect(usernamesRepositoryMock.getPublicProfile).toHaveBeenCalledWith('alice');
      expect(cacheMock.setProfile).toHaveBeenCalledWith('alice', profile);
    });

    it('does not cache null profiles', async () => {
      usernamesRepositoryMock.getPublicProfile!.mockResolvedValue(null);

      const result = await service.getPublicProfile('ghost');

      expect(result).toBeNull();
      expect(cacheMock.setProfile).not.toHaveBeenCalled();
    });

    it('normalizes username before lookup', async () => {
      usernamesRepositoryMock.getPublicProfile!.mockResolvedValue(profile);

      await service.getPublicProfile('Alice');

      expect(cacheMock.getProfile).toHaveBeenCalledWith('alice');
      expect(usernamesRepositoryMock.getPublicProfile).toHaveBeenCalledWith('alice');
    });
  });

  describe('search caching', () => {
    it('returns cached search results without hitting Supabase', async () => {
      const cached = [
        { id: '1', username: 'alice', public_key: 'pk', created_at: '', last_active_at: null, is_public: true },
      ];
      cacheMock.getSearchResults!.mockReturnValue(cached);
      usernamesRepositoryMock.updateUsernameActivity!.mockResolvedValue(undefined);

      const result = await service.searchPublicUsernames('alice', 10);

      expect(result.data).toEqual(cached);
      expect(usernamesRepositoryMock.searchPublicUsernames).not.toHaveBeenCalled();
    });

    it('fetches from Supabase and caches on miss', async () => {
      const fresh = [
        { id: '1', username: 'alice', public_key: 'pk', created_at: '', last_active_at: null, is_public: true },
      ];
      usernamesRepositoryMock.searchPublicUsernames!.mockResolvedValue(fresh);
      usernamesRepositoryMock.updateUsernameActivity!.mockResolvedValue(undefined);
      usernamesRepositoryMock.updateUsernameActivity!.mockResolvedValue(undefined);

      await service.searchPublicUsernames('alice', 10);

      expect(usernamesRepositoryMock.searchPublicUsernames).toHaveBeenCalled();
      expect(cacheMock.setSearchResults).toHaveBeenCalled();
    });
  });

  describe('trending caching', () => {
    it('returns cached trending results without hitting Supabase', async () => {
      cacheMock.getTrendingResults!.mockReturnValue([]);

      const result = await service.getTrendingCreators(24, 10);

      expect(result.data).toEqual([]);
      expect(usernamesRepositoryMock.getTrendingCreators).not.toHaveBeenCalled();
    });
  });

  describe('recently active caching', () => {
    it('returns cached recently active results without hitting Supabase', async () => {
      cacheMock.getRecentlyActiveResults!.mockReturnValue([]);

      const result = await service.getRecentlyActiveUsers(24, 10);

      expect(result.data).toEqual([]);
      expect(usernamesRepositoryMock.getRecentlyActiveUsers).not.toHaveBeenCalled();
    });
  });
});
