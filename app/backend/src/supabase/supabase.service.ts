import { Injectable, Logger } from "@nestjs/common";
import { createClient, SupabaseClient } from "@supabase/supabase-js";

import { AppConfigService } from "../config";
import {
  EscrowDbStatus,
  EscrowRecord,
  PaymentDbStatus,
  PaymentRecord,
} from "../reconciliation/types/reconciliation.types";
import {
  SupabaseError,
  SupabaseNetworkError,
  SupabaseUniqueConstraintError,
} from "./supabase.errors";

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

export interface MarketplaceBid {
  id: string;
  listing_id: string;
  bidder_public_key: string;
  bid_amount: number;
  status: 'pending' | 'accepted' | 'rejected' | 'cancelled';
  created_at: string;
  updated_at: string;
}

@Injectable()
export class SupabaseService {
  private readonly logger = new Logger(SupabaseService.name);
  private readonly client: SupabaseClient;

  constructor(private readonly configService: AppConfigService) {
    // Environment variables are validated at startup via Joi schema,
    // so we can safely access them here without null checks
    const url = this.configService.supabaseUrl;
    const anonKey = this.configService.supabaseAnonKey;

    this.client = createClient(url, anonKey, {
      auth: {
        persistSession: false,
      },
    });

    this.logger.log("Supabase client initialized successfully");
  }

  /**
   * Expose the underlying SupabaseClient for direct table access in repositories.
   */
  getClient(): SupabaseClient {
    return this.client;
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private handleError(error: any): never {
    if (error?.code === "23505") {
      throw new SupabaseUniqueConstraintError(
        error.message || "Unique constraint violation",
        error,
      );
    }
    // Match common network/timeout issues or PostgREST generic errors
    if (
      error?.message?.toLowerCase().includes("fetch") ||
      error?.message?.toLowerCase().includes("network") ||
      error?.code === "PGRST301"
    ) {
      throw new SupabaseNetworkError(
        error.message || "Network error connecting to Supabase",
        error,
      );
    }
    throw new SupabaseError(
      error?.message || "Unknown Supabase error",
      error?.code,
      error,
    );
  }

  async insertUsername(username: string, publicKey: string): Promise<void> {
    const { error } = await this.client.from("usernames").insert({
      username,
      public_key: publicKey,
    });
    if (error) this.handleError(error);
  }

  async countUsernamesByPublicKey(publicKey: string): Promise<number> {
    const { count, error } = await this.client
      .from("usernames")
      .select("*", { count: "exact", head: true })
      .eq("public_key", publicKey);
    if (error) this.handleError(error);
    return count ?? 0;
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  async listUsernamesByPublicKey(publicKey: string): Promise<any[]> {
    const { data, error } = await this.client
      .from("usernames")
      .select("id, username, public_key, created_at")
      .eq("public_key", publicKey)
      .order("created_at", { ascending: true });
    if (error) this.handleError(error);
    return data ?? [];
  }

  // ---------------------------------------------------------------------------
  // Reconciliation helpers
  // ---------------------------------------------------------------------------

  async fetchPendingEscrows(
    statuses: EscrowDbStatus[],
    limit: number,
  ): Promise<EscrowRecord[]> {
    const { data, error } = await this.client
      .from("escrow_records")
      .select("*")
      .in("status", statuses)
      .order("updated_at", { ascending: true })
      .limit(limit);
    if (error) this.handleError(error);
    return (data as EscrowRecord[]) ?? [];
  }

  async fetchPendingPayments(
    statuses: PaymentDbStatus[],
    limit: number,
  ): Promise<PaymentRecord[]> {
    const { data, error } = await this.client
      .from("payment_records")
      .select("*")
      .in("status", statuses)
      .order("updated_at", { ascending: true })
      .limit(limit);
    if (error) this.handleError(error);
    return (data as PaymentRecord[]) ?? [];
  }

  async updateEscrowStatus(id: string, status: EscrowDbStatus): Promise<void> {
    const { error } = await this.client
      .from("escrow_records")
      .update({ status, updated_at: new Date().toISOString() })
      .eq("id", id);
    if (error) this.handleError(error);
  }

  async updatePaymentStatus(
    id: string,
    status: PaymentDbStatus,
  ): Promise<void> {
    const { error } = await this.client
      .from("payment_records")
      .update({ status, updated_at: new Date().toISOString() })
      .eq("id", id);
    if (error) this.handleError(error);
  }

  async flagIrreconcilableEscrow(id: string, reason: string): Promise<void> {
    const { error } = await this.client
      .from("escrow_records")
      .update({
        status: "irreconcilable",
        reconciliation_note: reason,
        updated_at: new Date().toISOString(),
      })
      .eq("id", id);
    if (error) this.handleError(error);
  }

  async flagIrreconcilablePayment(id: string, reason: string): Promise<void> {
    const { error } = await this.client
      .from("payment_records")
      .update({
        status: "irreconcilable",
        reconciliation_note: reason,
        updated_at: new Date().toISOString(),
      })
      .eq("id", id);
    if (error) this.handleError(error);
  }

  async checkHealth(): Promise<boolean> {
    try {
      const { error } = await this.client
        .from("usernames")
        .select("id")
        .limit(1);
      if (error) {
        this.logger.warn(`Supabase health check failed: ${error.message}`);
        return false;
      }
      return true;
    } catch (err) {
      this.logger.warn(
        `Supabase health check threw an error: ${(err as Error).message}`,
      );
      return false;
    }
  }

  // ---------------------------------------------------------------------------
  // Public profile discovery helpers
  // ---------------------------------------------------------------------------

  /**
   * Search for public usernames with fuzzy matching using PostgreSQL trigram similarity
   */
  async searchPublicUsernames(
    query: string,
    limit: number = 10,
  ): Promise<SearchProfileResult[]> {
    const normalizedQuery = query.trim().toLowerCase();
    
    // Use PostgreSQL word_similarity for fuzzy matching
    // This requires the pg_trgm extension to be enabled
    const { data, error } = await this.client.rpc('search_usernames', {
      search_query: normalizedQuery,
      result_limit: limit,
    });
    
    if (error) {
      this.logger.warn(`PostgreSQL function search_usernames not available, using fallback: ${error.message}`);
      // Fallback: simple LIKE query with wildcards
      return this.searchUsernamesFallback(normalizedQuery, limit);
    }
    
    return data ?? [];
  }

  /**
   * Fallback search when pg_trgm is not available
   */
  private async searchUsernamesFallback(
    query: string,
    limit: number,
  ): Promise<SearchProfileResult[]> {
    // Escape special characters for LIKE query
    const escapedQuery = query.replace(/[%_]/g, '\\$&');
    const pattern = `%${escapedQuery}%`;
    
    const { data, error } = await this.client
      .from('usernames')
      .select('id, username, public_key, created_at, last_active_at, is_public')
      .eq('is_public', true)
      .ilike('username', pattern)
      .order('last_active_at', { ascending: false })
      .limit(limit);
    
    if (error) this.handleError(error);
    
    // Calculate simple similarity score based on position and length
    return (data ?? []).map((row: SearchProfileResult) => ({
      ...row,
      similarity_score: this.calculateSimpleSimilarity(row.username, query),
    })).sort((a: SearchProfileResult, b: SearchProfileResult) => (b.similarity_score ?? 0) - (a.similarity_score ?? 0));
  }

  /**
   * Calculate simple similarity score (0-100) for fallback search
   */
  private calculateSimpleSimilarity(username: string, query: string): number {
    const lowerUsername = username.toLowerCase();
    const lowerQuery = query.toLowerCase();
    
    // Exact match
    if (lowerUsername === lowerQuery) return 100;
    
    // Starts with query
    if (lowerUsername.startsWith(lowerQuery)) return 90;
    
    // Contains query
    if (lowerUsername.includes(lowerQuery)) return 75;
    
    // Partial match with some character overlap
    const commonChars = lowerUsername.split('').filter(c => lowerQuery.includes(c)).length;
    const maxLen = Math.max(lowerUsername.length, lowerQuery.length);
    return Math.round((commonChars / maxLen) * 100);
  }

  /**
   * Get trending creators based on transaction volume in a time window
   */
  async getTrendingCreators(
    timeWindowHours: number,
    limit: number = 10,
  ): Promise<TrendingCreatorResult[]> {
    const cutoffTime = new Date();
    cutoffTime.setHours(cutoffTime.getHours() - timeWindowHours);
    
    // Query payment_records and escrow_records for volume calculation
    const { data: payments, error: paymentsError } = await this.client
      .from('payment_records')
      .select('sender_public_key, receiver_public_key, amount_usd, created_at')
      .gte('created_at', cutoffTime.toISOString())
      .in('status', ['completed', 'pending']);
    
    if (paymentsError) {
      this.logger.warn(`Failed to fetch payment records: ${paymentsError.message}`);
    }
    
    // Aggregate volumes by public key
    const volumeMap = new Map<string, { volume: number; count: number }>();
    
    const processTransaction = (publicKey: string, amountUsd: number) => {
      if (!publicKey || amountUsd == null) return;
      
      const current = volumeMap.get(publicKey) || { volume: 0, count: 0 };
      current.volume += Number(amountUsd) || 0;
      current.count += 1;
      volumeMap.set(publicKey, current);
    };
    
    (payments ?? []).forEach((payment: { sender_public_key: string; receiver_public_key: string; amount_usd: number }) => {
      processTransaction(payment.sender_public_key, payment.amount_usd);
      processTransaction(payment.receiver_public_key, payment.amount_usd);
    });
    
    // Get top creators by volume
    const topCreators = Array.from(volumeMap.entries())
      .sort((a, b) => b[1].volume - a[1].volume)
      .slice(0, limit);
    
    // Fetch public profiles for these creators
    if (topCreators.length === 0) {
      return [];
    }
    
    const publicKeys = topCreators.map(([key]) => key);
    const { data: profiles, error: profilesError } = await this.client
      .from('usernames')
      .select('id, username, public_key, created_at, last_active_at, is_public')
      .in('public_key', publicKeys)
      .eq('is_public', true);
    
    if (profilesError) {
      this.logger.warn(`Failed to fetch profiles: ${profilesError.message}`);
      return [];
    }
    
    // Merge volume data with profile data
    return (profiles ?? []).map((profile: SearchProfileResult) => {
      const found = topCreators.find(([key]) => key === profile.public_key);
      const stats = found ? found[1] : { volume: 0, count: 0 };
      return {
        ...profile,
        transaction_volume: stats.volume,
        transaction_count: stats.count,
      } as TrendingCreatorResult;
    }).sort((a: TrendingCreatorResult, b: TrendingCreatorResult) => (b.transaction_volume || 0) - (a.transaction_volume || 0));
  }

  /**
   * Update last_active_at timestamp for a username
   */
  async updateUsernameActivity(username: string): Promise<void> {
    const { error } = await this.client
      .from('usernames')
      .update({ last_active_at: new Date().toISOString() })
      .eq('username', username);
    
    if (error) this.handleError(error);
  }

  /**
   * Toggle public profile visibility
   */
  async togglePublicProfile(
    username: string,
    isPublic: boolean,
  ): Promise<void> {
    const { error } = await this.client
      .from('usernames')
      .update({
        is_public: isPublic,
        last_active_at: new Date().toISOString(),
      })
      .eq('username', username);

    if (error) this.handleError(error);
  }

  async createListing(
    username: string,
    sellerPublicKey: string,
    askingPrice: number,
  ): Promise<MarketplaceListing> {
    const { data, error } = await this.client
      .from('username_marketplace')
      .insert({ username, seller_public_key: sellerPublicKey, asking_price: askingPrice })
      .select()
      .single();
    if (error) this.handleError(error);
    return data as MarketplaceListing;
  }

  async getActiveListings(limit: number, offset: number): Promise<{ listings: MarketplaceListing[]; total: number }> {
    const { data, error, count } = await this.client
      .from('username_marketplace')
      .select('*', { count: 'exact' })
      .eq('status', 'active')
      .order('created_at', { ascending: false })
      .range(offset, offset + limit - 1);
    if (error) this.handleError(error);
    return { listings: (data ?? []) as MarketplaceListing[], total: count ?? 0 };
  }

  async getListingById(listingId: string): Promise<MarketplaceListing | null> {
    const { data, error } = await this.client
      .from('username_marketplace')
      .select('*')
      .eq('id', listingId)
      .maybeSingle();
    if (error) this.handleError(error);
    return data as MarketplaceListing | null;
  }

  async getActiveListingByUsername(username: string): Promise<MarketplaceListing | null> {
    const { data, error } = await this.client
      .from('username_marketplace')
      .select('*')
      .eq('username', username)
      .eq('status', 'active')
      .maybeSingle();
    if (error) this.handleError(error);
    return data as MarketplaceListing | null;
  }

  async cancelListing(listingId: string): Promise<void> {
    const { error } = await this.client
      .from('username_marketplace')
      .update({ status: 'cancelled', updated_at: new Date().toISOString() })
      .eq('id', listingId);
    if (error) this.handleError(error);
  }

  async placeBid(listingId: string, bidderPublicKey: string, bidAmount: number): Promise<MarketplaceBid> {
    const { data, error } = await this.client
      .from('username_bids')
      .insert({ listing_id: listingId, bidder_public_key: bidderPublicKey, bid_amount: bidAmount })
      .select()
      .single();
    if (error) this.handleError(error);
    return data as MarketplaceBid;
  }

  async getBidsByListingId(listingId: string): Promise<MarketplaceBid[]> {
    const { data, error } = await this.client
      .from('username_bids')
      .select('*')
      .eq('listing_id', listingId)
      .order('bid_amount', { ascending: false });
    if (error) this.handleError(error);
    return (data ?? []) as MarketplaceBid[];
  }

  async getBidById(bidId: string): Promise<MarketplaceBid | null> {
    const { data, error } = await this.client
      .from('username_bids')
      .select('*')
      .eq('id', bidId)
      .maybeSingle();
    if (error) this.handleError(error);
    return data as MarketplaceBid | null;
  }

  async acceptBid(listingId: string, bidId: string, sellerPublicKey: string): Promise<void> {
    const { error } = await this.client.rpc('accept_username_bid', {
      p_listing_id: listingId,
      p_bid_id: bidId,
      p_seller_public_key: sellerPublicKey,
    });
    if (error) this.handleError(error);
  }
}
