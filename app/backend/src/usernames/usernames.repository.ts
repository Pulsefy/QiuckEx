/**
 * Usernames repository port.
 *
 * Defines the persistence contract the usernames domain depends on. Services
 * depend on the `UsernamesRepository` interface (via the `USERNAMES_REPOSITORY`
 * DI token) rather than on a concrete storage implementation, so unit tests can
 * substitute an in-memory fake without touching Supabase.
 *
 * The Supabase-backed adapter lives in the same file as the concrete
 * `SupabaseUsernamesRepository`.
 */

import { Injectable } from '@nestjs/common';

import { SupabaseService } from '../supabase/supabase.service';
import { SupabaseUniqueConstraintError } from '../supabase/supabase.errors';
import { UsernameConflictError } from './errors';

// ---------------------------------------------------------------------------
// Domain types (persistence shape for the usernames domain)
// ---------------------------------------------------------------------------

export interface SearchProfileResult {
  id: string;
  username: string;
  public_key: string;
  created_at: string;
  last_active_at: string | null;
  is_public: boolean;
  similarity_score?: number;
}

export interface TrendingCreatorResult extends SearchProfileResult {
  transaction_volume: number;
  transaction_count: number;
}

export interface FeaturedProfileResult extends SearchProfileResult {
  featured_rank: number | null;
}

export interface MarketplaceListing {
  id: string;
  username: string;
  seller_public_key: string;
  asking_price: number;
  status: 'active' | 'sold' | 'cancelled';
  created_at: string;
  updated_at: string;
  sold_at: string | null;
  buyer_public_key: string | null;
  final_price: number | null;
}

export interface UsernameRow {
  id: string;
  username: string;
  public_key: string;
  created_at: string;
}

export interface ListingPage {
  listings: MarketplaceListing[];
  next_cursor: string | null;
  has_more: boolean;
  total: number;
}

// ---------------------------------------------------------------------------
// Port
// ---------------------------------------------------------------------------

export interface UsernamesRepository {
  /**
   * Atomically claim a username and record the `username.claimed` domain event
   * in the outbox. Throws `UsernameConflictError` on a unique violation.
   */
  claimUsernameWithOutbox(
    username: string,
    publicKey: string,
    eventId: string,
    payload: Record<string, unknown>,
  ): Promise<void>;

  countUsernamesByPublicKey(publicKey: string): Promise<number>;
  listUsernamesByPublicKey(publicKey: string): Promise<UsernameRow[]>;
  getUsername(username: string): Promise<SearchProfileResult | null>;

  searchPublicUsernames(
    query: string,
    limit?: number,
  ): Promise<SearchProfileResult[]>;
  searchActiveListings(query: string, limit?: number): Promise<ListingPage>;
  getTrendingCreators(
    timeWindowHours: number,
    limit?: number,
  ): Promise<TrendingCreatorResult[]>;
  getRecentlyActiveUsers(
    timeWindowHours: number,
    limit?: number,
  ): Promise<SearchProfileResult[]>;
  getFeaturedUsernames(limit?: number): Promise<FeaturedProfileResult[]>;
  getPublicProfile(username: string): Promise<SearchProfileResult | null>;
  togglePublicProfile(username: string, isPublic: boolean): Promise<void>;
  updateUsernameActivity(username: string): Promise<void>;
}

export const USERNAMES_REPOSITORY = Symbol('USERNAMES_REPOSITORY');

// ---------------------------------------------------------------------------
// Supabase adapter
// ---------------------------------------------------------------------------

@Injectable()
export class SupabaseUsernamesRepository implements UsernamesRepository {
  constructor(private readonly supabase: SupabaseService) {}

  async claimUsernameWithOutbox(
    username: string,
    publicKey: string,
    eventId: string,
    payload: Record<string, unknown>,
  ): Promise<void> {
    try {
      await this.supabase.claimUsernameWithOutbox(
        username,
        publicKey,
        eventId,
        payload,
      );
    } catch (error) {
      if (error instanceof SupabaseUniqueConstraintError) {
        throw new UsernameConflictError(username);
      }
      throw error;
    }
  }

  countUsernamesByPublicKey(publicKey: string): Promise<number> {
    return this.supabase.countUsernamesByPublicKey(publicKey);
  }

  listUsernamesByPublicKey(publicKey: string): Promise<UsernameRow[]> {
    return this.supabase.listUsernamesByPublicKey(publicKey);
  }

  getUsername(username: string): Promise<SearchProfileResult | null> {
    return this.supabase.getUsername(username);
  }

  searchPublicUsernames(
    query: string,
    limit?: number,
  ): Promise<SearchProfileResult[]> {
    return this.supabase.searchPublicUsernames(query, limit);
  }

  searchActiveListings(query: string, limit?: number): Promise<ListingPage> {
    return this.supabase.searchActiveListings(query, limit);
  }

  getTrendingCreators(
    timeWindowHours: number,
    limit?: number,
  ): Promise<TrendingCreatorResult[]> {
    return this.supabase.getTrendingCreators(timeWindowHours, limit);
  }

  getRecentlyActiveUsers(
    timeWindowHours: number,
    limit?: number,
  ): Promise<SearchProfileResult[]> {
    return this.supabase.getRecentlyActiveUsers(timeWindowHours, limit);
  }

  getFeaturedUsernames(limit?: number): Promise<FeaturedProfileResult[]> {
    return this.supabase.getFeaturedUsernames(limit);
  }

  getPublicProfile(username: string): Promise<SearchProfileResult | null> {
    return this.supabase.getPublicProfile(username);
  }

  togglePublicProfile(username: string, isPublic: boolean): Promise<void> {
    return this.supabase.togglePublicProfile(username, isPublic);
  }

  updateUsernameActivity(username: string): Promise<void> {
    return this.supabase.updateUsernameActivity(username);
  }
}
