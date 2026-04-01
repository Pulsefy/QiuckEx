import { Injectable, Logger } from '@nestjs/common';
import { LRUCache } from 'lru-cache';
import { CachedAssetMetadata } from '../types/asset-metadata.types';

@Injectable()
export class AssetMetadataCache {
  private readonly logger = new Logger(AssetMetadataCache.name);
  private readonly cache: LRUCache<string, CachedAssetMetadata>;
  private readonly DEFAULT_TTL_MS = 1000 * 60 * 60 * 24; // 24 hours

  constructor() {
    this.cache = new LRUCache<string, CachedAssetMetadata>({
      max: 500, // Maximum 500 assets cached
      ttl: this.DEFAULT_TTL_MS,
      updateAgeOnGet: true,
      updateAgeOnHas: true,
    });
    this.logger.log('Asset metadata cache initialized');
  }

  /**
   * Get cached asset metadata by asset code
   */
  get(code: string): CachedAssetMetadata | undefined {
    const key = this.getCacheKey(code);
    const cached = this.cache.get(key);
    if (cached) {
      this.logger.debug(`Cache hit for asset: ${code}`);
    }
    return cached;
  }

  /**
   * Set asset metadata in cache
   */
  set(code: string, metadata: CachedAssetMetadata): void {
    const key = this.getCacheKey(code);
    this.cache.set(key, metadata);
    this.logger.debug(`Cached metadata for asset: ${code}`);
  }

  /**
   * Check if asset metadata is cached and not expired
   */
  has(code: string): boolean {
    const key = this.getCacheKey(code);
    return this.cache.has(key);
  }

  /**
   * Delete cached asset metadata
   */
  delete(code: string): boolean {
    const key = this.getCacheKey(code);
    return this.cache.delete(key);
  }

  /**
   * Clear all cached metadata
   */
  clear(): void {
    this.cache.clear();
    this.logger.log('Asset metadata cache cleared');
  }

  /**
   * Get cache statistics
   */
  getStats(): { size: number; maxSize: number; ttl: number } {
    return {
      size: this.cache.size,
      maxSize: this.cache.max,
      ttl: this.DEFAULT_TTL_MS,
    };
  }

  private getCacheKey(code: string): string {
    return `asset:${code.toUpperCase()}`;
  }
}
