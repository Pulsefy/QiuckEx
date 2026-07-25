import { describe, expect, it } from "vitest";

import {
  formatPublicKey,
  mapListingDetailToCardListing,
  type MarketplaceListingDetail,
} from "@/hooks/marketplaceApi";

const sampleDetail: MarketplaceListingDetail = {
  listing: {
    id: "listing-1",
    username: "nova",
    seller_public_key: "GSELLER1234567890SELLER1234567890SELLER12",
    asking_price: 100,
    status: "active",
    created_at: "2026-07-01T12:00:00.000Z",
    updated_at: "2026-07-01T12:00:00.000Z",
    sold_at: null,
    buyer_public_key: null,
    final_price: null,
  },
  bids: [
    {
      id: "bid-1",
      listing_id: "listing-1",
      bidder_public_key: "GBIDDER1234567890BIDDER1234567890BID12",
      bid_amount: 150,
      status: "pending",
      created_at: "2026-07-02T12:00:00.000Z",
      updated_at: "2026-07-02T12:00:00.000Z",
    },
  ],
  seller: {
    public_key: "GSELLER1234567890SELLER1234567890SELLER12",
    display_key: "GSEL...ER12",
  },
  state_hints: {
    can_place_bid: true,
    can_watchlist: true,
    can_buy_now: false,
    is_available: true,
    unavailable_reason: null,
    minimum_bid_amount: 151,
  },
};

describe("marketplace listing detail helpers", () => {
  it("formats stellar public keys for bid history rows", () => {
    expect(formatPublicKey("GBIDDER1234567890BIDDER1234567890BID12")).toBe("GBID...ID12");
  });

  it("maps backend detail into card listing bids and pricing", () => {
    const cardListing = mapListingDetailToCardListing(sampleDetail);

    expect(cardListing.id).toBe("listing-1");
    expect(cardListing.username).toBe("nova");
    expect(cardListing.currentBid).toBe(150);
    expect(cardListing.bidCount).toBe(1);
    expect(cardListing.ownerAddress).toBe("GSEL...ER12");
  });
});
