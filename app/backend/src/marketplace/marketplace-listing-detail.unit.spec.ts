import {
  buildMarketplaceStateHints,
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

describe('marketplace listing detail helpers', () => {
  it('truncates long stellar public keys', () => {
    expect(truncateStellarPublicKey(baseListing.seller_public_key)).toBe(
      'GSEL...ER12',
    );
  });

  it('uses asking price when no pending bids exist', () => {
    expect(resolveHighBidAmount(250, [])).toBe(250);
  });

  it('uses highest pending bid amount', () => {
    const bids: MarketplaceBid[] = [
      {
        id: 'b1',
        listing_id: 'listing-1',
        bidder_public_key: 'GBIDDER1',
        bid_amount: 120,
        status: 'pending',
        created_at: '2026-07-02T12:00:00.000Z',
        updated_at: '2026-07-02T12:00:00.000Z',
      },
      {
        id: 'b2',
        listing_id: 'listing-1',
        bidder_public_key: 'GBIDDER2',
        bid_amount: 180,
        status: 'rejected',
        created_at: '2026-07-02T13:00:00.000Z',
        updated_at: '2026-07-02T13:00:00.000Z',
      },
    ];

    expect(resolveHighBidAmount(100, bids)).toBe(120);
  });

  it('blocks bidding for seller and inactive listings', () => {
    const highBid = 150;
    const sellerHints = buildMarketplaceStateHints(
      baseListing,
      highBid,
      baseListing.seller_public_key,
    );
    expect(sellerHints.can_place_bid).toBe(false);
    expect(sellerHints.minimum_bid_amount).toBe(151);

    const soldHints = buildMarketplaceStateHints(
      { ...baseListing, status: 'sold' },
      highBid,
      'GBUYER',
    );
    expect(soldHints.is_available).toBe(false);
    expect(soldHints.can_place_bid).toBe(false);
    expect(soldHints.unavailable_reason).toContain('sold');
  });
});
