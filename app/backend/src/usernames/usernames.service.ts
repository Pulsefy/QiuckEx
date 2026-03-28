import { Injectable } from '@nestjs/common';
import { SupabaseService, SearchProfileResult, TrendingCreatorResult } from '../supabase/supabase.service';
import { SupabaseUniqueConstraintError } from '../supabase/supabase.errors';
import { AppConfigService } from '../config';
import {
  USERNAME_MIN_LENGTH,
  USERNAME_MAX_LENGTH,
  USERNAME_PATTERN,
} from './constants';
import {
  UsernameConflictError,
  UsernameLimitExceededError,
  UsernameValidationError,
  UsernameErrorCode,
} from './errors';

export interface UsernameRow {
  id: string;
  username: string;
  public_key: string;
  created_at: string;
}

@Injectable()
export class UsernamesService {
  constructor(
    private readonly supabase: SupabaseService,
    private readonly config: AppConfigService,
  ) { }

  /**
   * Normalize username for storage (lowercase).
   */
  normalizeUsername(username: string): string {
    return username.trim().toLowerCase();
  }

  /**
   * Validate format server-side (length and pattern). DTO already validates; this is a safeguard.
   */
  validateFormat(username: string): void {
    const normalized = this.normalizeUsername(username);
    if (normalized.length < USERNAME_MIN_LENGTH || normalized.length > USERNAME_MAX_LENGTH) {
      throw new UsernameValidationError(
        UsernameErrorCode.INVALID_FORMAT,
        `Username must be between ${USERNAME_MIN_LENGTH} and ${USERNAME_MAX_LENGTH} characters`,
        'username',
      );
    }
    if (!USERNAME_PATTERN.test(normalized)) {
      throw new UsernameValidationError(
        UsernameErrorCode.INVALID_FORMAT,
        `Username must contain only lowercase letters, numbers, and underscores`,
        'username',
      );
    }
  }

  async create(username: string, publicKey: string): Promise<{ ok: true }> {
    const normalized = this.normalizeUsername(username);
    this.validateFormat(username);

    const maxPerWallet = this.config.maxUsernamesPerWallet;
    if (typeof maxPerWallet === 'number' && maxPerWallet > 0) {
      const count = await this.countByPublicKey(publicKey);
      if (count >= maxPerWallet) {
        throw new UsernameLimitExceededError(publicKey, maxPerWallet);
      }
    }

    try {
      await this.supabase.insertUsername(normalized, publicKey);
    } catch (error) {
      if (error instanceof SupabaseUniqueConstraintError) {
        throw new UsernameConflictError(normalized);
      }
      throw error;
    }

    return { ok: true };
  }

  /**
   * Count usernames registered for a wallet (for limit enforcement).
   */
  async countByPublicKey(publicKey: string): Promise<number> {
    return this.supabase.countUsernamesByPublicKey(publicKey);
  }

  /**
   * List usernames for a wallet.
   */
  async listByPublicKey(publicKey: string): Promise<UsernameRow[]> {
    return this.supabase.listUsernamesByPublicKey(publicKey) as Promise<UsernameRow[]>;
  }

  /**
   * Search for public usernames with fuzzy matching.
   * Returns profiles sorted by similarity score.
   */
  async searchPublicUsernames(
    query: string,
    limit: number = 10,
  ): Promise<SearchProfileResult[]> {
    const normalizedQuery = this.normalizeUsername(query);

    if (!normalizedQuery || normalizedQuery.length < 2) {
      throw new UsernameValidationError(
        UsernameErrorCode.INVALID_FORMAT,
        'Search query must be at least 2 characters',
        'query',
      );
    }

    const results = await this.supabase.searchPublicUsernames(normalizedQuery, limit);

    // Update activity timestamp for clicked results (async, non-blocking)
    if (results.length > 0) {
      this.supabase.updateUsernameActivity(results[0].username).catch(() => {
        // Ignore errors - activity tracking is best-effort
      });
    }

    return results;
  }

  /**
   * Get trending creators based on transaction volume.
   * Defaults to last 24 hours, configurable via timeWindowHours.
   */
  async getTrendingCreators(
    timeWindowHours: number = 24,
    limit: number = 10,
  ): Promise<TrendingCreatorResult[]> {
    if (timeWindowHours < 1 || timeWindowHours > 720) {
      throw new UsernameValidationError(
        UsernameErrorCode.INVALID_FORMAT,
        'Time window must be between 1 and 720 hours',
        'timeWindowHours',
      );
    }

    return this.supabase.getTrendingCreators(timeWindowHours, limit);
  }

  /**
   * Toggle public profile visibility for a username.
   */
  async togglePublicProfile(
    username: string,
    publicKey: string,
    isPublic: boolean,
  ): Promise<void> {
    const normalized = this.normalizeUsername(username);

    // Verify ownership
    const usernames = await this.listByPublicKey(publicKey);
    const owned = usernames.find(u => u.username === normalized);

    if (!owned) {
      throw new UsernameValidationError(
        UsernameErrorCode.NOT_FOUND,
        'Username not found or does not belong to this wallet',
        'username',
      );
    }

    await this.supabase.togglePublicProfile(normalized, isPublic);
  }
}
