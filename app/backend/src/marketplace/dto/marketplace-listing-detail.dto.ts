import { MarketplaceListing, MarketplaceBid } from '../../supabase/supabase.service';

export type BidSummary = {
  total_bids: number;
  pending_bids: number;
  highest_bid: number | null;
  lowest_bid: number | null;
};

export type MarketplaceListingDetailDto = {
  listing: MarketplaceListing;
  bids: MarketplaceBid[];
  bid_summary: BidSummary;
  seller: {
    public_key: string;
    display_key: string;
  };
  state_hints: {
    can_place_bid: boolean;
    can_cancel: boolean;
    can_accept_bids: boolean;
    can_watchlist: boolean;
    can_buy_now: boolean;
    is_available: boolean;
    unavailable_reason: string | null;
    minimum_bid_amount: number;
  };
};
