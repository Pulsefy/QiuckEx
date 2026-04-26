import { Injectable, Logger } from '@nestjs/common';
import { LRUCache } from 'lru-cache';
import { SearchProfileResult, TrendingCreatorResult } from '../../supabase/supabase.service';

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

@Injectable()
export class DiscoveryCacheService {
  private readonly logger = new Logger(DiscoveryCacheService.name);
  private readonly searchCache: LRUCache<string, CachedSearchResult>;
  private readonly trendingCache: LRUCache<string, CachedTrendingResult>;
  private readonly recentlyActiveCache: LRUCache<string, CachedRecentlyActiveResult>;
  
  private readonly SEARCH_TTL_MS = 1000 * 60 * 15; // 15 minutes
  private readonly TRENDING_TTL_MS = 1000 * 60 * 30; // 30 minutes
  private readonly RECENTLY_ACTIVE_TTL_MS = 1000 * 60 * 10; // 10 minutes

  constructor() {
    this.searchCache = new LRUCache<string, CachedSearchResult>({
      max: 1000, // Maximum 1000 search queries cached
      ttl: this.SEARCH_TTL_MS,
      updateAgeOnGet: true,
    });

    this.trendingCache = new LRUCache<string, CachedTrendingResult>({
      max: 100, // Maximum 100 different trending queries cached
      ttl: this.TRENDING_TTL_MS,
      updateAgeOnGet: true,
    });

    this.recentlyActiveCache = new LRUCache<string, CachedRecentlyActiveResult>({
      max: 100, // Maximum 100 different recently active queries cached
      ttl: this.RECENTLY_ACTIVE_TTL_MS,
      updateAgeOnGet: true,
    });

    this.logger.log('Discovery cache service initialized');
  }

  // Search cache methods
  getSearchResults(query: string, limit: number): SearchProfileResult[] | undefined {
    const key = this.getSearchCacheKey(query, limit);
    const cached = this.searchCache.get(key);
    if (cached) {
      this.logger.debug(`Search cache hit for query: ${query}`);
      return cached.results;
    }
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
      this.logger.debug(`Trending cache hit for window: ${timeWindowHours}h`);
      return cached.results;
    }
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
      this.logger.debug(`Recently active cache hit for window: ${timeWindowHours}h`);
      return cached.results;
    }
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

  // Cache statistics
  getStats(): {
    search: { size: number; maxSize: number; ttl: number };
    trending: { size: number; maxSize: number; ttl: number };
    recentlyActive: { size: number; maxSize: number; ttl: number };
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
}
