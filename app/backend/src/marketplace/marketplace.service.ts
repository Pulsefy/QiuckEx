import { Injectable } from '@nestjs/common';
import { SupabaseService, MarketplaceListing, MarketplaceBid } from '../supabase/supabase.service';
import { SupabaseUniqueConstraintError } from '../supabase/supabase.errors';
import { UsernamesService } from '../usernames/usernames.service';
import { MarketplaceError, MarketplaceErrorCode } from './errors';

@Injectable()
export class MarketplaceService {
  constructor(
    private readonly supabase: SupabaseService,
    private readonly usernames: UsernamesService,
  ) {}

  async listUsername(
    username: string,
    sellerPublicKey: string,
    askingPrice: number,
  ): Promise<MarketplaceListing> {
    const normalized = username.trim().toLowerCase();

    const owned = await this.usernames.listByPublicKey(sellerPublicKey);
    if (!owned.find((u) => u.username === normalized)) {
      throw new MarketplaceError(
        MarketplaceErrorCode.USERNAME_NOT_OWNED,
        'Username not found or does not belong to this wallet',
      );
    }

    const existing = await this.supabase.getActiveListingByUsername(normalized);
    if (existing) {
      throw new MarketplaceError(
        MarketplaceErrorCode.ALREADY_LISTED,
        'Username already has an active listing',
      );
    }

    try {
      return await this.supabase.createListing(normalized, sellerPublicKey, askingPrice);
    } catch (err) {
      if (err instanceof SupabaseUniqueConstraintError) {
        throw new MarketplaceError(
          MarketplaceErrorCode.ALREADY_LISTED,
          'Username already has an active listing',
        );
      }
      throw err;
    }
  }

  async getActiveListings(
    limit: number = 20,
    cursor: string | null = null,
  ): Promise<{ listings: MarketplaceListing[]; total: number; next_cursor: string | null; has_more: boolean }> {
    return this.supabase.getActiveListings(limit, cursor);
  }

  async getListing(listingId: string): Promise<MarketplaceListing> {
    const listing = await this.supabase.getListingById(listingId);
    if (!listing) {
      throw new MarketplaceError(
        MarketplaceErrorCode.LISTING_NOT_FOUND,
        'Listing not found',
      );
    }
    return listing;
  }

  async cancelListing(listingId: string, sellerPublicKey: string): Promise<void> {
    const listing = await this.getListing(listingId);

    if (listing.seller_public_key !== sellerPublicKey) {
      throw new MarketplaceError(
        MarketplaceErrorCode.UNAUTHORIZED,
        'Only the seller can cancel this listing',
      );
    }

    if (listing.status !== 'active') {
      throw new MarketplaceError(
        MarketplaceErrorCode.LISTING_NOT_ACTIVE,
        'Only active listings can be cancelled',
      );
    }

    await this.supabase.cancelListing(listingId);
  }

  async placeBid(
    listingId: string,
    bidderPublicKey: string,
    bidAmount: number,
  ): Promise<MarketplaceBid> {
    const listing = await this.getListing(listingId);

    if (listing.status !== 'active') {
      throw new MarketplaceError(
        MarketplaceErrorCode.LISTING_NOT_ACTIVE,
        'Listing is no longer active',
      );
    }

    if (listing.seller_public_key === bidderPublicKey) {
      throw new MarketplaceError(
        MarketplaceErrorCode.SELF_BID,
        'Seller cannot bid on their own listing',
      );
    }

    return this.supabase.placeBid(listingId, bidderPublicKey, bidAmount);
  }

  async getBids(listingId: string, limit: number = 20, cursor: string | null = null): Promise<{ bids: MarketplaceBid[]; next_cursor: string | null; has_more: boolean }> {
    await this.getListing(listingId);
    return this.supabase.getBidsByListingIdPaginated(listingId, limit, cursor);
  }

  async acceptBid(
    listingId: string,
    bidId: string,
    sellerPublicKey: string,
  ): Promise<void> {
    const listing = await this.getListing(listingId);

    if (listing.seller_public_key !== sellerPublicKey) {
      throw new MarketplaceError(
        MarketplaceErrorCode.UNAUTHORIZED,
        'Only the seller can accept a bid',
      );
    }

    if (listing.status !== 'active') {
      throw new MarketplaceError(
        MarketplaceErrorCode.LISTING_NOT_ACTIVE,
        'Listing is no longer active',
      );
    }

    const bid = await this.supabase.getBidById(bidId);
    if (!bid || bid.listing_id !== listingId) {
      throw new MarketplaceError(
        MarketplaceErrorCode.BID_NOT_FOUND,
        'Bid not found on this listing',
      );
    }

    if (bid.status !== 'pending') {
      throw new MarketplaceError(
        MarketplaceErrorCode.BID_NOT_PENDING,
        'Bid is no longer pending',
      );
    }

    await this.supabase.acceptBid(listingId, bidId, sellerPublicKey);
  }
}
