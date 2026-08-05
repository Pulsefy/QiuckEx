import { DiscoveryCacheService } from './discovery-cache.service';

describe('DiscoveryCacheService', () => {
  let service: DiscoveryCacheService;

  beforeEach(() => {
    service = new DiscoveryCacheService();
  });

  describe('profile cache', () => {
    const profile = {
      id: 'id-1',
      username: 'alice',
      public_key: 'pk1',
      created_at: '2025-01-01T00:00:00Z',
      last_active_at: null,
      is_public: true,
    };

    it('returns undefined on cache miss', () => {
      expect(service.getProfile('alice')).toBeUndefined();
    });

    it('returns cached profile on hit', () => {
      service.setProfile('alice', profile);
      expect(service.getProfile('alice')).toEqual(profile);
    });

    it('invalidates a single profile', () => {
      service.setProfile('alice', profile);
      service.invalidateProfile('alice');
      expect(service.getProfile('alice')).toBeUndefined();
    });

    it('does not invalidate other profiles', () => {
      service.setProfile('alice', profile);
      service.setProfile('bob', { ...profile, username: 'bob' });
      service.invalidateProfile('alice');
      expect(service.getProfile('bob')).toBeDefined();
    });
  });

  describe('invalidateForUsername', () => {
    it('removes the profile cache entry', () => {
      const profile = {
        id: 'id-1',
        username: 'alice',
        public_key: 'pk1',
        created_at: '2025-01-01T00:00:00Z',
        last_active_at: null,
        is_public: true,
      };
      service.setProfile('alice', profile);
      service.invalidateForUsername('alice');
      expect(service.getProfile('alice')).toBeUndefined();
    });

    it('clears search cache entries containing the username', () => {
      service.setSearchResults('alice', 10, [
        { id: '1', username: 'alice', public_key: 'pk', created_at: '', last_active_at: null, is_public: true },
      ]);
      service.invalidateForUsername('alice');
      expect(service.getSearchResults('alice', 10)).toBeUndefined();
    });

    it('clears trending cache', () => {
      service.setTrendingResults(24, 10, []);
      service.invalidateForUsername('alice');
      expect(service.getTrendingResults(24, 10)).toBeUndefined();
    });

    it('clears recently active cache', () => {
      service.setRecentlyActiveResults(24, 10, []);
      service.invalidateForUsername('alice');
      expect(service.getRecentlyActiveResults(24, 10)).toBeUndefined();
    });
  });

  describe('hit/miss tracking', () => {
    it('tracks search hits and misses', () => {
      service.getSearchResults('alice', 10); // miss
      service.setSearchResults('alice', 10, []);
      service.getSearchResults('alice', 10); // hit

      const stats = service.getStats();
      expect(stats.hitMiss.search.hits).toBe(1);
      expect(stats.hitMiss.search.misses).toBe(1);
    });

    it('tracks profile hits and misses', () => {
      service.getProfile('alice'); // miss
      service.setProfile('alice', {
        id: '1', username: 'alice', public_key: 'pk', created_at: '', last_active_at: null, is_public: true,
      });
      service.getProfile('alice'); // hit

      const stats = service.getStats();
      expect(stats.hitMiss.profile.hits).toBe(1);
      expect(stats.hitMiss.profile.misses).toBe(1);
    });

    it('tracks trending hits and misses', () => {
      service.getTrendingResults(24, 10); // miss
      service.setTrendingResults(24, 10, []);
      service.getTrendingResults(24, 10); // hit

      const stats = service.getStats();
      expect(stats.hitMiss.trending.hits).toBe(1);
      expect(stats.hitMiss.trending.misses).toBe(1);
    });

    it('tracks recently active hits and misses', () => {
      service.getRecentlyActiveResults(24, 10); // miss
      service.setRecentlyActiveResults(24, 10, []);
      service.getRecentlyActiveResults(24, 10); // hit

      const stats = service.getStats();
      expect(stats.hitMiss.recentlyActive.hits).toBe(1);
      expect(stats.hitMiss.recentlyActive.misses).toBe(1);
    });
  });

  describe('getStats', () => {
    it('returns profile cache size and config', () => {
      service.setProfile('alice', {
        id: '1', username: 'alice', public_key: 'pk', created_at: '', last_active_at: null, is_public: true,
      });
      const stats = service.getStats();
      expect(stats.profile.size).toBe(1);
      expect(stats.profile.maxSize).toBe(2000);
      expect(stats.profile.ttl).toBe(1000 * 60 * 5);
    });
  });
});
