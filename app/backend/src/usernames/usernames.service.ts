import { Injectable } from "@nestjs/common";
import {
  SupabaseService,
  SearchProfileResult,
  TrendingCreatorResult,
} from "../supabase/supabase.service";
import { decodeCursor } from "../common/pagination/cursor.util";
import { SupabaseUniqueConstraintError } from "../supabase/supabase.errors";
import { AppConfigService } from "../config";
import { DiscoveryCacheService } from "./cache/discovery-cache.service";
import {
  USERNAME_MIN_LENGTH,
  USERNAME_MAX_LENGTH,
  USERNAME_PATTERN,
} from "./constants";
import {
  UsernameConflictError,
  UsernameLimitExceededError,
  UsernameValidationError,
  UsernameErrorCode,
} from "./errors";

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
    private readonly cache: DiscoveryCacheService,
  ) {}

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
    if (
      normalized.length < USERNAME_MIN_LENGTH ||
      normalized.length > USERNAME_MAX_LENGTH
    ) {
      throw new UsernameValidationError(
        UsernameErrorCode.INVALID_FORMAT,
        `Username must be between ${USERNAME_MIN_LENGTH} and ${USERNAME_MAX_LENGTH} characters`,
        "username",
      );
    }
    if (!USERNAME_PATTERN.test(normalized)) {
      throw new UsernameValidationError(
        UsernameErrorCode.INVALID_FORMAT,
        `Username must contain only lowercase letters, numbers, and underscores`,
        "username",
      );
    }
  }

  async create(username: string, publicKey: string): Promise<{ ok: true }> {
    const normalized = this.normalizeUsername(username);
    this.validateFormat(username);

    const maxPerWallet = this.config.maxUsernamesPerWallet;
    if (typeof maxPerWallet === "number" && maxPerWallet > 0) {
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
    return this.supabase.listUsernamesByPublicKey(publicKey) as Promise<
      UsernameRow[]
    >;
  }

  /**
   * Search for public usernames with fuzzy matching.
   * Returns profiles sorted by similarity score.
   */
  async searchPublicUsernames(
    query: string,
    limit: number = 10,
    cursor?: string,
  ): Promise<{ data: SearchProfileResult[]; next_cursor: string | null; has_more: boolean }> {
    const normalizedQuery = this.normalizeUsername(query);

    // Validate cursor format if provided (actual filtering handled by limit+1 strategy)
    if (cursor) {
      decodeCursor(cursor);
    }

    if (!normalizedQuery || normalizedQuery.length < 2) {
      throw new UsernameValidationError(
        UsernameErrorCode.INVALID_FORMAT,
        "Search query must be at least 2 characters",
        "query",
      );
    }

    // For search endpoints, fetch limit+1 results to detect has_more
    const effectiveLimit = Math.min(100, Math.max(1, limit));
    const results = await this.supabase.searchPublicUsernames(
      normalizedQuery,
      effectiveLimit + 1,
    );

    const hasMore = results.length > effectiveLimit;
    const data = hasMore ? results.slice(0, effectiveLimit) : results;

    let nextCursor: string | null = null;
    if (hasMore && data.length > 0) {
      const last = data[data.length - 1];
      nextCursor = Buffer.from(
        JSON.stringify({ pk: last.created_at, id: last.id }),
        "utf-8",
      ).toString("base64url");
    }

    // Update activity timestamp for clicked results (async, non-blocking)
    if (data.length > 0) {
      this.supabase.updateUsernameActivity(data[0].username).catch(() => {
        // Ignore errors - activity tracking is best-effort
      });
    }

    return { data, next_cursor: nextCursor, has_more: hasMore };
  }

  /**
   * Get trending creators based on transaction volume.
   * Defaults to last 24 hours, configurable via timeWindowHours.
   */
  async getTrendingCreators(
    timeWindowHours: number = 24,
    limit: number = 10,
    cursor?: string,
  ): Promise<{ data: TrendingCreatorResult[]; next_cursor: string | null; has_more: boolean }> {
    // Validate cursor format if provided (actual filtering handled by limit+1 strategy)
    if (cursor) {
      decodeCursor(cursor);
    }

    if (timeWindowHours < 1 || timeWindowHours > 720) {
      throw new UsernameValidationError(
        UsernameErrorCode.INVALID_FORMAT,
        "Time window must be between 1 and 720 hours",
        "timeWindowHours",
      );
    }

    const effectiveLimit = Math.min(100, Math.max(1, limit));
    const results = await this.supabase.getTrendingCreators(
      timeWindowHours,
      effectiveLimit + 1,
    );

    const hasMore = results.length > effectiveLimit;
    const data = hasMore ? results.slice(0, effectiveLimit) : results;

    let nextCursor: string | null = null;
    if (hasMore && data.length > 0) {
      const last = data[data.length - 1];
      nextCursor = Buffer.from(
        JSON.stringify({ pk: last.created_at, id: last.id }),
        "utf-8",
      ).toString("base64url");
    }

    return { data, next_cursor: nextCursor, has_more: hasMore };
  }

  /**
   * Get recently active users based on payment activity and profile updates.
   * Defaults to last 24 hours, configurable via timeWindowHours.
   */
  async getRecentlyActiveUsers(
    timeWindowHours: number = 24,
    limit: number = 10,
    cursor?: string,
  ): Promise<{ data: SearchProfileResult[]; next_cursor: string | null; has_more: boolean }> {
    // Validate cursor format if provided (actual filtering handled by limit+1 strategy)
    if (cursor) {
      decodeCursor(cursor);
    }

    if (timeWindowHours < 1 || timeWindowHours > 168) {
      throw new UsernameValidationError(
        UsernameErrorCode.INVALID_FORMAT,
        "Time window must be between 1 and 168 hours",
        "timeWindowHours",
      );
    }

    const effectiveLimit = Math.min(100, Math.max(1, limit));
    const results = await this.supabase.getRecentlyActiveUsers(
      timeWindowHours,
      effectiveLimit + 1,
    );

    const hasMore = results.length > effectiveLimit;
    const data = hasMore ? results.slice(0, effectiveLimit) : results;

    let nextCursor: string | null = null;
    if (hasMore && data.length > 0) {
      const last = data[data.length - 1];
      nextCursor = Buffer.from(
        JSON.stringify({ pk: last.created_at, id: last.id }),
        "utf-8",
      ).toString("base64url");
    }

    return { data, next_cursor: nextCursor, has_more: hasMore };
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
    const owned = usernames.find((u) => u.username === normalized);

    if (!owned) {
      throw new UsernameValidationError(
        UsernameErrorCode.NOT_FOUND,
        "Username not found or does not belong to this wallet",
        "username",
      );
    }

    await this.supabase.togglePublicProfile(normalized, isPublic);
  }
}
