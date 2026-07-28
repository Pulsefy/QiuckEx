import { Injectable, Logger } from '@nestjs/common';
import { LRUCache } from 'lru-cache';
import { BranchPreviewEnvironment } from './branch-preview.model';

@Injectable()
export class BranchPreviewCache {
  private readonly logger = new Logger(BranchPreviewCache.name);
  private readonly cache: LRUCache<string, BranchPreviewEnvironment>;
  private readonly DEFAULT_TTL_MS = 1000 * 60 * 60 * 24 * 7; // 7 days default
  private readonly FALLBACK_TTL_MS = 1000 * 60 * 15; // 15 minutes for fallback caching

  constructor() {
    this.cache = new LRUCache<string, BranchPreviewEnvironment>({
      max: 1000, // Maximum 1000 branch previews cached
      ttl: this.DEFAULT_TTL_MS,
      updateAgeOnGet: true,
      updateAgeOnHas: true,
    });
    this.logger.log('Branch preview cache initialized');
  }

  /**
   * Get cached branch preview environment by branch name
   */
  get(branchName: string): BranchPreviewEnvironment | undefined {
    const key = this.getCacheKey(branchName);
    const cached = this.cache.get(key);
    if (cached) {
      this.logger.debug(`Cache hit for branch: ${branchName}`);
    }
    return cached;
  }

  /**
   * Set branch preview environment in cache with custom TTL if provided
   */
  set(branchName: string, preview: BranchPreviewEnvironment, ttlMs?: number): void {
    const key = this.getCacheKey(branchName);
    const ttl = ttlMs || (preview.expiresAt 
      ? Math.max(0, new Date(preview.expiresAt).getTime() - Date.now())
      : this.DEFAULT_TTL_MS);
    this.cache.set(key, preview, { ttl });
    this.logger.debug(`Cached preview for branch: ${branchName} with TTL: ${ttl}ms`);
  }

  /**
   * Check if branch preview is cached and not expired
   */
  has(branchName: string): boolean {
    const key = this.getCacheKey(branchName);
    return this.cache.has(key);
  }

  /**
   * Delete cached branch preview
   */
  delete(branchName: string): boolean {
    const key = this.getCacheKey(branchName);
    const deleted = this.cache.delete(key);
    if (deleted) {
      this.logger.debug(`Invalidated cache for branch: ${branchName}`);
    }
    return deleted;
  }

  /**
   * Clear entire cache
   */
  clear(): void {
    this.cache.clear();
    this.logger.warn('Cleared entire branch preview cache');
  }

  /**
   * Create cache key from branch name
   */
  private getCacheKey(branchName: string): string {
    return `branch-preview:${branchName.toLowerCase().trim()}`;
  }
}