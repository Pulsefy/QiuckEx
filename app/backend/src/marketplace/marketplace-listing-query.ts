import { MarketplaceBid, MarketplaceListing } from '../supabase/supabase.service';
import { BidSummary } from './dto/marketplace-listing-detail.dto';
import { buildBidSummary, resolveHighBidAmount } from './marketplace-listing-detail';

/**
 * Sort options supported by GET /marketplace.
 */
export type MarketplaceSortOption = 'newest' | 'ending_soon' | 'price_asc' | 'price_desc';

export const MARKETPLACE_SORT_OPTIONS: MarketplaceSortOption[] = [
  'newest',
  'ending_soon',
  'price_asc',
  'price_desc',
];

export const DEFAULT_MARKETPLACE_SORT: MarketplaceSortOption = 'newest';

/**
 * Fixed listing duration used by the frontend to derive `endsAt` from
 * `createdAt` (see mapBackendListingToCardListing in marketplaceApi.ts).
 * The `username_marketplace` table has no expiry column of its own, so we
 * mirror that same fixed 48h offset here rather than introduce a schema
 * migration. Because the offset is constant, sorting by "ending soonest"
 * is mathematically identical to sorting by `created_at` ascending.
 */
export const LISTING_DURATION_MS = 1000 * 60 * 60 * 48;

/**
 * Derive the (client-assumed) expiry timestamp for a listing.
 */
export function computeEndsAt(createdAt: string): string {
  return new Date(new Date(createdAt).getTime() + LISTING_DURATION_MS).toISOString();
}

/**
 * The DB column and direction to order by for a given sort option.
 *
 * Note: price sorting orders by the stored `asking_price` column rather
 * than the live current bid. Ordering by a value that can change between
 * page fetches (the current highest bid) would make cursor pagination
 * unstable — a listing could jump across the cursor boundary between
 * requests as new bids come in. `asking_price` is immutable for the
 * lifetime of an active listing, so it keeps pagination stable enough to
 * cache, per the acceptance criteria.
 */
export function resolveSortColumn(
  sort: MarketplaceSortOption,
): { column: 'created_at' | 'asking_price'; ascending: boolean } {
  switch (sort) {
    case 'ending_soon':
      return { column: 'created_at', ascending: true };
    case 'price_asc':
      return { column: 'asking_price', ascending: true };
    case 'price_desc':
      return { column: 'asking_price', ascending: false };
    case 'newest':
    default:
      return { column: 'created_at', ascending: false };
  }
}

export type MarketplaceListingSummary = MarketplaceListing & {
  ends_at: string;
  current_price: number;
  bid_summary: BidSummary;
};

/**
 * Group a flat list of bids by their listing id for O(1) lookup while
 * attaching bid data to a page of listings.
 */
export function groupBidsByListingId(bids: MarketplaceBid[]): Map<string, MarketplaceBid[]> {
  const map = new Map<string, MarketplaceBid[]>();
  for (const bid of bids) {
    const existing = map.get(bid.listing_id);
    if (existing) {
      existing.push(bid);
    } else {
      map.set(bid.listing_id, [bid]);
    }
  }
  return map;
}

/**
 * Merge per-listing bid data (summary + resolved current price) and the
 * derived `ends_at` timestamp into a page of listings. Reuses the same
 * bid-aggregation logic as the listing detail endpoint so summary and
 * detail views never disagree on what "current price" or "bid summary"
 * mean.
 */
export function attachBidData(
  listings: MarketplaceListing[],
  bidsByListingId: Map<string, MarketplaceBid[]>,
): MarketplaceListingSummary[] {
  return listings.map((listing) => {
    const bids = bidsByListingId.get(listing.id) ?? [];
    return {
      ...listing,
      ends_at: computeEndsAt(listing.created_at),
      current_price: resolveHighBidAmount(Number(listing.asking_price), bids),
      bid_summary: buildBidSummary(bids),
    };
  });
}
