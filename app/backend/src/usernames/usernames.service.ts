import { Injectable } from "@nestjs/common";
import {
  SupabaseService,
  SearchProfileResult,
  TrendingCreatorResult,
  FeaturedProfileResult,
  MarketplaceListing,
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

  async searchDiscovery(
    query: string,
    limit: number = 10,
    cursor?: string,
  ): Promise<{ results: Array<{ kind: 'profile' | 'listing'; id: string; username: string; publicKey?: string; sellerPublicKey?: string; similarityScore?: number; askingPrice?: number; status?: string; lastActiveAt?: string; createdAt: string; }>; total: number; next_cursor: string | null; has_more: boolean; empty: boolean }> {
    const normalizedQuery = this.normalizeUsername(query);

    if (!normalizedQuery || normalizedQuery.length < 2) {
      return {
        results: [],
        total: 0,
        next_cursor: null,
        has_more: false,
        empty: true,
      };
    }

    const effectiveLimit = Math.min(100, Math.max(1, limit));
    const decodedCursor = cursor ? decodeCursor(cursor) : null;
    const fetchWindow = decodedCursor ? 100 : effectiveLimit + 1;

    const [profilesResult, listingsResult] = await Promise.all([
      this.supabase.searchPublicUsernames(normalizedQuery, fetchWindow),
      this.supabase.searchActiveListings(normalizedQuery, fetchWindow),
    ]);

    const profileResults = profilesResult.map((profile) => ({
      kind: 'profile' as const,
      id: profile.id,
      username: profile.username,
      publicKey: profile.public_key,
      similarityScore: profile.similarity_score,
      lastActiveAt: profile.last_active_at || profile.created_at,
      createdAt: profile.created_at,
    }));

    const listingResults = listingsResult.listings.map((listing: MarketplaceListing) => ({
      kind: 'listing' as const,
      id: listing.id,
      username: listing.username,
      sellerPublicKey: listing.seller_public_key,
      askingPrice: listing.asking_price,
      status: listing.status,
      createdAt: listing.created_at,
    }));

    const combined = [...profileResults, ...listingResults].sort((a, b) => {
      const scoreA = a.kind === 'profile' ? (a.similarityScore ?? 0) : 0;
      const scoreB = b.kind === 'profile' ? (b.similarityScore ?? 0) : 0;
      if (scoreA !== scoreB) {
        return scoreB - scoreA;
      }

      const timeA = new Date(a.createdAt).getTime();
      const timeB = new Date(b.createdAt).getTime();
      return timeB - timeA;
    });

    const hasMore = combined.length > effectiveLimit;
    const data = hasMore ? combined.slice(0, effectiveLimit) : combined;

    let nextCursor: string | null = null;
    if (hasMore && data.length > 0) {
      const last = data[data.length - 1];
      nextCursor = Buffer.from(
        JSON.stringify({ pk: last.createdAt, id: last.id }),
        'utf-8',
      ).toString('base64url');
    }

    return {
      results: data,
      total: combined.length,
      next_cursor: nextCursor,
      has_more: hasMore,
      empty: data.length === 0,
    };
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

    const decodedCursor = cursor ? decodeCursor(cursor) : null;

    if (!normalizedQuery || normalizedQuery.length < 2) {
      throw new UsernameValidationError(
        UsernameErrorCode.INVALID_FORMAT,
        "Search query must be at least 2 characters",
        "query",
      );
    }

    const effectiveLimit = Math.min(100, Math.max(1, limit));
    const fetchWindow = decodedCursor ? 100 : effectiveLimit + 1;

    const cachedResults = this.cache.getSearchResults(normalizedQuery, fetchWindow);
    let results: SearchProfileResult[];
    if (cachedResults) {
      results = cachedResults;
    } else {
      results = await this.supabase.searchPublicUsernames(
        normalizedQuery,
        fetchWindow,
      );
      this.cache.setSearchResults(normalizedQuery, fetchWindow, results);
    }

    let windowed = results;
    if (decodedCursor) {
      const cursorIndex = results.findIndex(
        (row) =>
          row.id === decodedCursor.id && row.created_at === decodedCursor.pk,
      );
      if (cursorIndex >= 0) {
        windowed = results.slice(cursorIndex + 1);
      } else {
        // Fallback comparator for cursor continuity when the exact row is no longer in range.
        windowed = results.filter(
          (row) =>
            row.created_at < decodedCursor.pk ||
            (row.created_at === decodedCursor.pk && row.id < decodedCursor.id),
        );
      }
    }

    const hasMore = windowed.length > effectiveLimit;
    const data = hasMore ? windowed.slice(0, effectiveLimit) : windowed;

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
    const decodedCursor = cursor ? decodeCursor(cursor) : null;

    if (timeWindowHours < 1 || timeWindowHours > 720) {
      throw new UsernameValidationError(
        UsernameErrorCode.INVALID_FORMAT,
        "Time window must be between 1 and 720 hours",
        "timeWindowHours",
      );
    }

    const effectiveLimit = Math.min(100, Math.max(1, limit));
    const fetchWindow = decodedCursor ? 100 : effectiveLimit + 1;

    const cachedResults = this.cache.getTrendingResults(timeWindowHours, fetchWindow);
    let results: TrendingCreatorResult[];
    if (cachedResults) {
      results = cachedResults;
    } else {
      results = await this.supabase.getTrendingCreators(
        timeWindowHours,
        fetchWindow,
      );
      this.cache.setTrendingResults(timeWindowHours, fetchWindow, results);
    }

    let windowed = results;
    if (decodedCursor) {
      const cursorVolume = Number(decodedCursor.pk);
      const cursorIndex = results.findIndex(
        (row) =>
          row.id === decodedCursor.id &&
          row.transaction_volume === cursorVolume,
      );
      if (cursorIndex >= 0) {
        windowed = results.slice(cursorIndex + 1);
      } else {
        // Fallback comparator for cursor continuity when the exact row is no
        // longer in range (matches the volume DESC, id ASC ranking order).
        windowed = results.filter((row) =>
          row.transaction_volume !== cursorVolume
            ? row.transaction_volume < cursorVolume
            : row.id > decodedCursor.id,
        );
      }
    }

    const hasMore = windowed.length > effectiveLimit;
    const data = hasMore ? windowed.slice(0, effectiveLimit) : windowed;

    let nextCursor: string | null = null;
    if (hasMore && data.length > 0) {
      const last = data[data.length - 1];
      nextCursor = Buffer.from(
        JSON.stringify({ pk: String(last.transaction_volume), id: last.id }),
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
    const decodedCursor = cursor ? decodeCursor(cursor) : null;

    if (timeWindowHours < 1 || timeWindowHours > 168) {
      throw new UsernameValidationError(
        UsernameErrorCode.INVALID_FORMAT,
        "Time window must be between 1 and 168 hours",
        "timeWindowHours",
      );
    }

    const effectiveLimit = Math.min(100, Math.max(1, limit));
    const fetchWindow = decodedCursor ? 100 : effectiveLimit + 1;

    const cachedResults = this.cache.getRecentlyActiveResults(timeWindowHours, fetchWindow);
    let results: SearchProfileResult[];
    if (cachedResults) {
      results = cachedResults;
    } else {
      results = await this.supabase.getRecentlyActiveUsers(
        timeWindowHours,
        fetchWindow,
      );
      this.cache.setRecentlyActiveResults(timeWindowHours, fetchWindow, results);
    }

    let windowed = results;
    if (decodedCursor) {
      const cursorIndex = results.findIndex(
        (row) =>
          row.id === decodedCursor.id &&
          (row.last_active_at || row.created_at) === decodedCursor.pk,
      );
      if (cursorIndex >= 0) {
        windowed = results.slice(cursorIndex + 1);
      } else {
        // Fallback comparator for cursor continuity when the exact row is no
        // longer in range (matches the last_active_at DESC, id ASC ranking).
        windowed = results.filter((row) => {
          const rowKey = row.last_active_at || row.created_at;
          return rowKey !== decodedCursor.pk
            ? rowKey < decodedCursor.pk
            : row.id > decodedCursor.id;
        });
      }
    }

    const hasMore = windowed.length > effectiveLimit;
    const data = hasMore ? windowed.slice(0, effectiveLimit) : windowed;

    let nextCursor: string | null = null;
    if (hasMore && data.length > 0) {
      const last = data[data.length - 1];
      nextCursor = Buffer.from(
        JSON.stringify({
          pk: last.last_active_at || last.created_at,
          id: last.id,
        }),
        "utf-8",
      ).toString("base64url");
    }

    return { data, next_cursor: nextCursor, has_more: hasMore };
  }

  /**
   * Get curated/featured creators for discovery.
   * Ordered by manual `featured_rank` (ascending, nulls last) with `id` as a
   * deterministic tiebreaker.
   */
  async getFeaturedCreators(
    limit: number = 10,
    cursor?: string,
  ): Promise<{ data: FeaturedProfileResult[]; next_cursor: string | null; has_more: boolean }> {
    const decodedCursor = cursor ? decodeCursor(cursor) : null;

    const effectiveLimit = Math.min(100, Math.max(1, limit));
    const fetchWindow = decodedCursor ? 100 : effectiveLimit + 1;
    const results = await this.supabase.getFeaturedUsernames(fetchWindow);

    let windowed = results;
    if (decodedCursor) {
      const cursorRank =
        decodedCursor.pk === "" ? null : Number(decodedCursor.pk);
      const cursorIndex = results.findIndex(
        (row) => row.id === decodedCursor.id,
      );
      if (cursorIndex >= 0) {
        windowed = results.slice(cursorIndex + 1);
      } else {
        // Fallback comparator for cursor continuity when the exact row is no
        // longer in range (matches featured_rank ASC nulls-last, id ASC).
        const rankValue = (rank: number | null) =>
          rank === null ? Number.MAX_SAFE_INTEGER : rank;
        windowed = results.filter((row) => {
          const rowRank = rankValue(row.featured_rank);
          const targetRank = rankValue(cursorRank);
          return rowRank !== targetRank
            ? rowRank > targetRank
            : row.id > decodedCursor.id;
        });
      }
    }

    const hasMore = windowed.length > effectiveLimit;
    const data = hasMore ? windowed.slice(0, effectiveLimit) : windowed;

    let nextCursor: string | null = null;
    if (hasMore && data.length > 0) {
      const last = data[data.length - 1];
      nextCursor = Buffer.from(
        JSON.stringify({
          pk: last.featured_rank === null ? "" : String(last.featured_rank),
          id: last.id,
        }),
        "utf-8",
      ).toString("base64url");
    }

    return { data, next_cursor: nextCursor, has_more: hasMore };
  }

  /**
   * Fetch a single public profile by username, with caching and privacy checks.
   */
  async getPublicProfile(
    username: string,
  ): Promise<SearchProfileResult & { paymentSettings?: { acceptedAssets: string[]; defaultAsset: string } }> {
    const rawUsername = username ? username.trim().replace(/^@/, "") : "";
    const normalized = this.normalizeUsername(rawUsername);

    if (!normalized) {
      throw new UsernameValidationError(
        UsernameErrorCode.INVALID_FORMAT,
        "Username parameter is required",
        "username",
      );
    }

    const cached = this.cache.getProfile(normalized);
    if (cached) {
      if (!cached.is_public) {
        throw new UsernameValidationError(
          UsernameErrorCode.PRIVACY_DISABLED,
          "Public profile is disabled for this user",
          "username",
        );
      }
      return {
        ...cached,
        paymentSettings: {
          acceptedAssets: ["USDC", "XLM", "AQUA", "yXLM"],
          defaultAsset: "USDC",
        },
      };
    }

    const profile = await this.supabase.getPublicProfile(normalized);
    if (!profile) {
      throw new UsernameValidationError(
        UsernameErrorCode.NOT_FOUND,
        "Username not found",
        "username",
      );
    }

    if (!profile.is_public) {
      throw new UsernameValidationError(
        UsernameErrorCode.PRIVACY_DISABLED,
        "Public profile is disabled for this user",
        "username",
      );
    }

    this.cache.setProfile(normalized, profile);

    return {
      ...profile,
      paymentSettings: {
        acceptedAssets: ["USDC", "XLM", "AQUA", "yXLM"],
        defaultAsset: "USDC",
      },
    };
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

    // Invalidate all caches that may contain this username so visibility
    // changes are reflected immediately on subsequent reads.
    this.cache.invalidateForUsername(normalized);
  }

  async getProfileByUsername(username: string): Promise<SearchProfileResult> {
    const normalized = this.normalizeUsername(username);
    this.validateFormat(normalized);

    const result = await this.supabase.getUsername(normalized);
    if (!result) {
      throw new UsernameValidationError(
        UsernameErrorCode.NOT_FOUND,
        "Username not found",
        "username",
      );
    }

    return result;
  }
}
