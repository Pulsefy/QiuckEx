import { MarketplaceBid, MarketplaceListing } from '../supabase/supabase.service';

export type MarketplaceStateHints = {
  can_place_bid: boolean;
  can_watchlist: boolean;
  can_buy_now: boolean;
  is_available: boolean;
  unavailable_reason: string | null;
  minimum_bid_amount: number;
};

export type MarketplaceSellerInfo = {
  public_key: string;
  display_key: string;
};

export type MarketplaceListingDetail = {
  listing: MarketplaceListing;
  bids: MarketplaceBid[];
  seller: MarketplaceSellerInfo;
  state_hints: MarketplaceStateHints;
};

export function truncateStellarPublicKey(publicKey: string): string {
  if (publicKey.length <= 12) {
    return publicKey;
  }
  return `${publicKey.slice(0, 4)}...${publicKey.slice(-4)}`;
}

export function resolveHighBidAmount(
  askingPrice: number,
  bids: MarketplaceBid[],
): number {
  const pendingHigh = bids.reduce((max, bid) => {
    if (bid.status !== 'pending') {
      return max;
    }
    return Math.max(max, Number(bid.bid_amount));
  }, 0);

  if (pendingHigh > 0) {
    return pendingHigh;
  }
  return askingPrice;
}

export function buildMarketplaceStateHints(
  listing: MarketplaceListing,
  highBidAmount: number,
  viewerPublicKey?: string | null,
): MarketplaceStateHints {
  const isActive = listing.status === 'active';
  let unavailableReason: string | null = null;

  if (!isActive) {
    unavailableReason =
      listing.status === 'sold'
        ? 'This listing has been sold.'
        : 'This listing is no longer available.';
  }

  const isSeller =
    Boolean(viewerPublicKey) && listing.seller_public_key === viewerPublicKey;

  return {
    can_place_bid: isActive && !isSeller,
    can_watchlist: isActive,
    can_buy_now: false,
    is_available: isActive,
    unavailable_reason: unavailableReason,
    minimum_bid_amount: highBidAmount + 1,
  };
}
