import {
  buildMarketplaceStateHints,
  buildBidSummary,
  resolveHighBidAmount,
  truncateStellarPublicKey,
} from './marketplace-listing-detail';
import { MarketplaceBid, MarketplaceListing } from '../supabase/supabase.service';

const baseListing: MarketplaceListing = {
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
};

const makeBid = (
  id: string,
  amount: number,
  status: MarketplaceBid['status'],
): MarketplaceBid => ({
  id,
  listing_id: 'listing-1',
  bidder_public_key: 'GBIDDER',
  bid_amount: amount,
  status,
  created_at: '2026-07-02T12:00:00.000Z',
  updated_at: '2026-07-02T12:00:00.000Z',
});

describe('marketplace listing detail helpers', () => {
  describe('truncateStellarPublicKey', () => {
    it('truncates long stellar public keys', () => {
      expect(truncateStellarPublicKey(baseListing.seller_public_key)).toBe(
        'GSEL...ER12',
      );
    });

    it('returns short keys unchanged', () => {
      expect(truncateStellarPublicKey('SHORT')).toBe('SHORT');
    });
  });

  describe('resolveHighBidAmount', () => {
    it('uses asking price when no pending bids exist', () => {
      expect(resolveHighBidAmount(250, [])).toBe(250);
    });

    it('uses highest pending bid amount', () => {
      const bids: MarketplaceBid[] = [
        makeBid('b1', 120, 'pending'),
        makeBid('b2', 180, 'rejected'),
      ];

      expect(resolveHighBidAmount(100, bids)).toBe(120);
    });

    it('ignores accepted and rejected bids', () => {
      const bids: MarketplaceBid[] = [
        makeBid('b1', 300, 'accepted'),
        makeBid('b2', 100, 'pending'),
      ];

      expect(resolveHighBidAmount(50, bids)).toBe(100);
    });
  });

  describe('buildBidSummary', () => {
    it('returns empty summary when there are no bids', () => {
      const summary = buildBidSummary([]);
      expect(summary).toEqual({
        total_bids: 0,
        pending_bids: 0,
        highest_bid: null,
        lowest_bid: null,
      });
    });

    it('summarizes pending bids correctly', () => {
      const bids: MarketplaceBid[] = [
        makeBid('b1', 120, 'pending'),
        makeBid('b2', 200, 'pending'),
        makeBid('b3', 150, 'rejected'),
        makeBid('b4', 180, 'accepted'),
      ];

      const summary = buildBidSummary(bids);
      expect(summary).toEqual({
        total_bids: 4,
        pending_bids: 2,
        highest_bid: 200,
        lowest_bid: 120,
      });
    });

    it('returns null highest/lowest when no pending bids', () => {
      const bids: MarketplaceBid[] = [
        makeBid('b1', 120, 'rejected'),
        makeBid('b2', 200, 'accepted'),
      ];

      const summary = buildBidSummary(bids);
      expect(summary).toEqual({
        total_bids: 2,
        pending_bids: 0,
        highest_bid: null,
        lowest_bid: null,
      });
    });
  });

  describe('buildMarketplaceStateHints', () => {
    it('allows bidding for non-seller on active listing', () => {
      const hints = buildMarketplaceStateHints(baseListing, 150, 'GBUYER');
      expect(hints.can_place_bid).toBe(true);
      expect(hints.can_cancel).toBe(false);
      expect(hints.can_accept_bids).toBe(false);
      expect(hints.is_available).toBe(true);
      expect(hints.minimum_bid_amount).toBe(151);
    });

    it('blocks bidding for seller', () => {
      const hints = buildMarketplaceStateHints(
        baseListing,
        150,
        baseListing.seller_public_key,
      );
      expect(hints.can_place_bid).toBe(false);
      expect(hints.can_cancel).toBe(true);
      expect(hints.can_accept_bids).toBe(true);
      expect(hints.is_available).toBe(true);
    });

    it('blocks all actions for sold listing', () => {
      const hints = buildMarketplaceStateHints(
        { ...baseListing, status: 'sold' },
        150,
        'GBUYER',
      );
      expect(hints.is_available).toBe(false);
      expect(hints.can_place_bid).toBe(false);
      expect(hints.can_cancel).toBe(false);
      expect(hints.can_accept_bids).toBe(false);
      expect(hints.unavailable_reason).toContain('sold');
    });

    it('blocks all actions for cancelled listing', () => {
      const hints = buildMarketplaceStateHints(
        { ...baseListing, status: 'cancelled' },
        150,
        'GBUYER',
      );
      expect(hints.is_available).toBe(false);
      expect(hints.can_place_bid).toBe(false);
      expect(hints.can_cancel).toBe(false);
      expect(hints.can_accept_bids).toBe(false);
      expect(hints.unavailable_reason).toContain('no longer available');
    });

    it('sets minimum bid amount to highBidAmount + 1', () => {
      const hints = buildMarketplaceStateHints(baseListing, 200, 'GBUYER');
      expect(hints.minimum_bid_amount).toBe(201);
    });
  });
});
