import { Injectable, Logger } from '@nestjs/common';
import { LRUCache } from 'lru-cache';
import {
  SearchProfileResult,
  TrendingCreatorResult,
} from '../usernames.repository';

interface CachedSearchResult {
  results: SearchProfileResult[];
  timestamp: number;
}

interface CachedTrendingResult {
  results: TrendingCreatorResult[];
  timestamp: number;
}

interface CachedRecentlyActiveResult {
  results: SearchProfileResult[];
  timestamp: number;
}

export interface CacheHitMissStats {
  hits: number;
  misses: number;
}

@Injectable()
export class DiscoveryCacheService {
  private readonly logger = new Logger(DiscoveryCacheService.name);
  private readonly searchCache: LRUCache<string, CachedSearchResult>;
  private readonly trendingCache: LRUCache<string, CachedTrendingResult>;
  private readonly recentlyActiveCache: LRUCache<string, CachedRecentlyActiveResult>;
  private readonly profileCache: LRUCache<string, SearchProfileResult>;

  private readonly SEARCH_TTL_MS = 1000 * 60 * 15; // 15 minutes
  private readonly TRENDING_TTL_MS = 1000 * 60 * 30; // 30 minutes
  private readonly RECENTLY_ACTIVE_TTL_MS = 1000 * 60 * 10; // 10 minutes
  private readonly PROFILE_TTL_MS = 1000 * 60 * 5; // 5 minutes

  private readonly hitMiss = {
    search: { hits: 0, misses: 0 },
    trending: { hits: 0, misses: 0 },
    recentlyActive: { hits: 0, misses: 0 },
    profile: { hits: 0, misses: 0 },
  };

  constructor() {
    this.searchCache = new LRUCache<string, CachedSearchResult>({
      max: 1000,
      ttl: this.SEARCH_TTL_MS,
      updateAgeOnGet: true,
    });

    this.trendingCache = new LRUCache<string, CachedTrendingResult>({
      max: 100,
      ttl: this.TRENDING_TTL_MS,
      updateAgeOnGet: true,
    });

    this.recentlyActiveCache = new LRUCache<string, CachedRecentlyActiveResult>({
      max: 100,
      ttl: this.RECENTLY_ACTIVE_TTL_MS,
      updateAgeOnGet: true,
    });

    this.profileCache = new LRUCache<string, SearchProfileResult>({
      max: 2000,
      ttl: this.PROFILE_TTL_MS,
      updateAgeOnGet: true,
    });

    this.logger.log('Discovery cache service initialized');
  }

  // Search cache methods
  getSearchResults(query: string, limit: number): SearchProfileResult[] | undefined {
    const key = this.getSearchCacheKey(query, limit);
    const cached = this.searchCache.get(key);
    if (cached) {
      this.hitMiss.search.hits++;
      this.logger.debug(`Search cache hit for query: ${query}`);
      return cached.results;
    }
    this.hitMiss.search.misses++;
    return undefined;
  }

  setSearchResults(query: string, limit: number, results: SearchProfileResult[]): void {
    const key = this.getSearchCacheKey(query, limit);
    this.searchCache.set(key, {
      results,
      timestamp: Date.now(),
    });
    this.logger.debug(`Cached search results for query: ${query}`);
  }

  // Trending cache methods
  getTrendingResults(timeWindowHours: number, limit: number): TrendingCreatorResult[] | undefined {
    const key = this.getTrendingCacheKey(timeWindowHours, limit);
    const cached = this.trendingCache.get(key);
    if (cached) {
      this.hitMiss.trending.hits++;
      this.logger.debug(`Trending cache hit for window: ${timeWindowHours}h`);
      return cached.results;
    }
    this.hitMiss.trending.misses++;
    return undefined;
  }

  setTrendingResults(timeWindowHours: number, limit: number, results: TrendingCreatorResult[]): void {
    const key = this.getTrendingCacheKey(timeWindowHours, limit);
    this.trendingCache.set(key, {
      results,
      timestamp: Date.now(),
    });
    this.logger.debug(`Cached trending results for window: ${timeWindowHours}h`);
  }

  // Recently active cache methods
  getRecentlyActiveResults(timeWindowHours: number, limit: number): SearchProfileResult[] | undefined {
    const key = this.getRecentlyActiveCacheKey(timeWindowHours, limit);
    const cached = this.recentlyActiveCache.get(key);
    if (cached) {
      this.hitMiss.recentlyActive.hits++;
      this.logger.debug(`Recently active cache hit for window: ${timeWindowHours}h`);
      return cached.results;
    }
    this.hitMiss.recentlyActive.misses++;
    return undefined;
  }

  setRecentlyActiveResults(timeWindowHours: number, limit: number, results: SearchProfileResult[]): void {
    const key = this.getRecentlyActiveCacheKey(timeWindowHours, limit);
    this.recentlyActiveCache.set(key, {
      results,
      timestamp: Date.now(),
    });
    this.logger.debug(`Cached recently active results for window: ${timeWindowHours}h`);
  }

  // Public profile cache methods
  getProfile(username: string): SearchProfileResult | undefined {
    const key = this.getProfileCacheKey(username);
    const cached = this.profileCache.get(key);
    if (cached) {
      this.hitMiss.profile.hits++;
      this.logger.debug(`Profile cache hit for username: ${username}`);
      return cached;
    }
    this.hitMiss.profile.misses++;
    return undefined;
  }

  setProfile(username: string, profile: SearchProfileResult): void {
    const key = this.getProfileCacheKey(username);
    this.profileCache.set(key, profile);
    this.logger.debug(`Cached profile for username: ${username}`);
  }

  // Cache invalidation methods
  invalidateSearchCache(query?: string): void {
    if (query) {
      const keysToDelete: string[] = [];
      for (const key of this.searchCache.keys()) {
        if (key.includes(query.toLowerCase())) {
          keysToDelete.push(key);
        }
      }
      keysToDelete.forEach(key => this.searchCache.delete(key));
      this.logger.debug(`Invalidated search cache for query: ${query}`);
    } else {
      this.searchCache.clear();
      this.logger.log('Cleared all search cache');
    }
  }

  invalidateTrendingCache(): void {
    this.trendingCache.clear();
    this.logger.log('Cleared trending cache');
  }

  invalidateRecentlyActiveCache(): void {
    this.recentlyActiveCache.clear();
    this.logger.log('Cleared recently active cache');
  }

  invalidateProfile(username: string): void {
    const key = this.getProfileCacheKey(username);
    this.profileCache.delete(key);
    this.logger.debug(`Invalidated profile cache for username: ${username}`);
  }

  /**
   * Invalidate all caches that could contain a given username.
   * Called on profile updates and visibility changes to prevent stale reads.
   */
  invalidateForUsername(username: string): void {
    this.invalidateProfile(username);
    this.invalidateSearchCache(username);
    this.invalidateTrendingCache();
    this.invalidateRecentlyActiveCache();
    this.logger.log(`Invalidated all caches for username: ${username}`);
  }

  // Cache statistics
  getStats(): {
    search: { size: number; maxSize: number; ttl: number };
    trending: { size: number; maxSize: number; ttl: number };
    recentlyActive: { size: number; maxSize: number; ttl: number };
    profile: { size: number; maxSize: number; ttl: number };
    hitMiss: typeof this.hitMiss;
  } {
    return {
      search: {
        size: this.searchCache.size,
        maxSize: this.searchCache.max,
        ttl: this.SEARCH_TTL_MS,
      },
      trending: {
        size: this.trendingCache.size,
        maxSize: this.trendingCache.max,
        ttl: this.TRENDING_TTL_MS,
      },
      recentlyActive: {
        size: this.recentlyActiveCache.size,
        maxSize: this.recentlyActiveCache.max,
        ttl: this.RECENTLY_ACTIVE_TTL_MS,
      },
      profile: {
        size: this.profileCache.size,
        maxSize: this.profileCache.max,
        ttl: this.PROFILE_TTL_MS,
      },
      hitMiss: { ...this.hitMiss },
    };
  }

  // Private cache key generation methods
  private getSearchCacheKey(query: string, limit: number): string {
    return `search:${query.toLowerCase()}:${limit}`;
  }

  private getTrendingCacheKey(timeWindowHours: number, limit: number): string {
    return `trending:${timeWindowHours}:${limit}`;
  }

  private getRecentlyActiveCacheKey(timeWindowHours: number, limit: number): string {
    return `recent:${timeWindowHours}:${limit}`;
  }

  private getProfileCacheKey(username: string): string {
    return `profile:${username.toLowerCase()}`;
  }
}
