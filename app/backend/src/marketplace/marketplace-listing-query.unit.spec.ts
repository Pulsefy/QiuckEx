import { MarketplaceBid, MarketplaceListing } from '../supabase/supabase.service';
import {
  attachBidData,
  computeEndsAt,
  groupBidsByListingId,
  LISTING_DURATION_MS,
  MARKETPLACE_SORT_OPTIONS,
  resolveSortColumn,
} from './marketplace-listing-query';

const makeListing = (overrides: Partial<MarketplaceListing> = {}): MarketplaceListing => ({
  id: 'listing-1',
  username: 'nova',
  seller_public_key: 'GSELLER1234567890SELLER1234567890SELLER12',
  asking_price: 100,
  status: 'active',
  created_at: '2026-07-01T12:00:00.000Z',
  updated_at: '2026-07-01T12:00:00.000Z',
  sold_at: null,
  buyer_public_key: null,
  final_price: null,
  ...overrides,
});

const makeBid = (
  id: string,
  listingId: string,
  amount: number,
  status: MarketplaceBid['status'],
): MarketplaceBid => ({
  id,
  listing_id: listingId,
  bidder_public_key: 'GBIDDER',
  bid_amount: amount,
  status,
  created_at: '2026-07-02T12:00:00.000Z',
  updated_at: '2026-07-02T12:00:00.000Z',
});

describe('marketplace-listing-query', () => {
  describe('computeEndsAt', () => {
    it('adds the fixed 48h listing duration to created_at', () => {
      const createdAt = '2026-07-01T12:00:00.000Z';
      const endsAt = computeEndsAt(createdAt);
      expect(new Date(endsAt).getTime() - new Date(createdAt).getTime()).toBe(
        LISTING_DURATION_MS,
      );
      expect(endsAt).toBe('2026-07-03T12:00:00.000Z');
    });
  });

  describe('resolveSortColumn', () => {
    it('sorts newest by created_at descending', () => {
      expect(resolveSortColumn('newest')).toEqual({
        column: 'created_at',
        ascending: false,
      });
    });

    it('sorts ending_soon by created_at ascending (fixed offset from created_at)', () => {
      expect(resolveSortColumn('ending_soon')).toEqual({
        column: 'created_at',
        ascending: true,
      });
    });

    it('sorts price_asc by asking_price ascending', () => {
      expect(resolveSortColumn('price_asc')).toEqual({
        column: 'asking_price',
        ascending: true,
      });
    });

    it('sorts price_desc by asking_price descending', () => {
      expect(resolveSortColumn('price_desc')).toEqual({
        column: 'asking_price',
        ascending: false,
      });
    });

    it('defaults unknown values to newest', () => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      expect(resolveSortColumn('bogus' as any)).toEqual({
        column: 'created_at',
        ascending: false,
      });
    });

    it('covers every declared sort option without throwing', () => {
      for (const sort of MARKETPLACE_SORT_OPTIONS) {
        expect(() => resolveSortColumn(sort)).not.toThrow();
      }
    });
  });

  describe('groupBidsByListingId', () => {
    it('groups bids by listing id', () => {
      const bids = [
        makeBid('b1', 'listing-1', 100, 'pending'),
        makeBid('b2', 'listing-2', 200, 'pending'),
        makeBid('b3', 'listing-1', 150, 'rejected'),
      ];

      const grouped = groupBidsByListingId(bids);
      expect(grouped.get('listing-1')).toHaveLength(2);
      expect(grouped.get('listing-2')).toHaveLength(1);
      expect(grouped.get('listing-3')).toBeUndefined();
    });

    it('returns an empty map for an empty bid list', () => {
      expect(groupBidsByListingId([]).size).toBe(0);
    });
  });

  describe('attachBidData', () => {
    it('attaches ends_at, current_price, and bid_summary to each listing', () => {
      const listing = makeListing({ id: 'listing-1', asking_price: 100 });
      const bids = [
        makeBid('b1', 'listing-1', 120, 'pending'),
        makeBid('b2', 'listing-1', 90, 'rejected'),
      ];
      const bidsByListingId = groupBidsByListingId(bids);

      const [result] = attachBidData([listing], bidsByListingId);

      expect(result.ends_at).toBe(computeEndsAt(listing.created_at));
      expect(result.current_price).toBe(120);
      expect(result.bid_summary).toEqual({
        total_bids: 2,
        pending_bids: 1,
        highest_bid: 120,
        lowest_bid: 120,
      });
      // original listing fields are preserved
      expect(result.id).toBe('listing-1');
      expect(result.username).toBe('nova');
    });

    it('falls back to asking_price as current_price when a listing has no bids', () => {
      const listing = makeListing({ id: 'listing-2', asking_price: 300 });
      const [result] = attachBidData([listing], groupBidsByListingId([]));

      expect(result.current_price).toBe(300);
      expect(result.bid_summary).toEqual({
        total_bids: 0,
        pending_bids: 0,
        highest_bid: null,
        lowest_bid: null,
      });
    });

    it('preserves listing order and maps each listing independently', () => {
      const listingA = makeListing({ id: 'a', asking_price: 50 });
      const listingB = makeListing({ id: 'b', asking_price: 75 });
      const bidsByListingId = groupBidsByListingId([
        makeBid('b1', 'b', 999, 'pending'),
      ]);

      const results = attachBidData([listingA, listingB], bidsByListingId);

      expect(results.map((r) => r.id)).toEqual(['a', 'b']);
      expect(results[0].current_price).toBe(50); // no bids -> asking price
      expect(results[1].current_price).toBe(999); // has a pending bid
    });

    it('returns an empty array for an empty listing page', () => {
      expect(attachBidData([], groupBidsByListingId([]))).toEqual([]);
    });
  });
});
