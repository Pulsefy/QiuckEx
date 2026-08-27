import { getQuickexApiBase } from "@/lib/api";
import { resolvePublicKey } from "@/lib/publicKey";
export type UsernameStatus = "auction" | "buyNow" | "sold" | "listed";

export type MarketplaceListing = {
  id: string;
  username: string;
  currentBid: number;
  buyNowPrice: number | null;
  ownerAddress: string;
  endsAt: Date;
  createdAt: Date; // Added for sorting by newest
  status: UsernameStatus;
  category: "trending" | "short" | "og" | "crypto" | "brand";
  bidCount: number;
  watchers: number;
  verified: boolean;
};

export type UserBid = {
  listingId: string;
  username: string;
  myBid: number;
  currentBid: number;
  endsAt: Date;
  isWinning: boolean;
  status: BackendMarketplaceBid["status"];
};

export type UserListing = {
  username: string;
  minBid: number;
  currentBid: number;
  bidCount: number;
  endsAt: Date;
};

let cachedListings: MarketplaceListing[] | null = null;
export function mapBackendListingToCardListing(item: BackendMarketplaceListing): MarketplaceListing {
  const createdAt = new Date(item.created_at || Date.now());
  let hash = 0;
  const keyStr = item.id || item.username || "";
  for (let i = 0; i < keyStr.length; i++) {
    hash = (hash << 5) - hash + keyStr.charCodeAt(i);
    hash |= 0;
  }
  const absHash = Math.abs(hash);
  const currentBid = Number(item.asking_price) || 0;

  const lower = item.username.toLowerCase();
  let category: "trending" | "short" | "og" | "crypto" | "brand" = "trending";
  if (item.username.length <= 3) category = "short";
  else if (["satoshi", "btc", "eth", "sol", "defi", "web3"].includes(lower)) category = "crypto";
  else if (["pay", "alex", "john", "dev"].includes(lower)) category = "og";
  else if (["nova", "lux", "apex", "star"].includes(lower)) category = "brand";

  return {
    id: item.id,
    username: item.username,
    currentBid,
    buyNowPrice: Number(item.asking_price) || null,
    ownerAddress: item.seller_public_key ? formatPublicKey(item.seller_public_key) : "GDRH...4T9F",
    endsAt: new Date(createdAt.getTime() + 1000 * 60 * 60 * 48),
    createdAt,
    status: item.status === "active" ? "auction" : item.status === "sold" ? "sold" : "listed",
    category,
    bidCount: absHash % 15,
    watchers: (absHash % 100) + 5,
    verified: item.username.length <= 4 || ["satoshi", "pay", "sol", "web3"].includes(lower),
  };
}

export type FetchListingsOptions = {
  limit?: number;
  cursor?: string;
  bypassCache?: boolean;
};

export async function fetchListings(options: FetchListingsOptions = {}): Promise<MarketplaceListing[]> {
  const { limit = 100, cursor, bypassCache = false } = options;

  if (!bypassCache && cachedListings) {
    return cachedListings;
  }

  const url = new URL(`${getQuickexApiBase()}/marketplace`);
  url.searchParams.set("limit", limit.toString());
  if (cursor) {
    url.searchParams.set("cursor", cursor);
  }

  try {
    const response = await fetch(url.toString(), {
      method: "GET",
      headers: { Accept: "application/json" },
    });

    if (!response.ok) {
      throw new Error(`Failed to load marketplace listings (${response.status})`);
    }

    const data = (await response.json()) as {
      listings: BackendMarketplaceListing[];
      total: number;
      next_cursor: string | null;
      has_more: boolean;
    };

    const mapped = (data.listings || []).map(mapBackendListingToCardListing);
    cachedListings = mapped;
    return mapped;
  } catch (err) {
    throw err;
  }
}

export async function fetchUserBids(publicKey = resolvePublicKey()): Promise<UserBid[]> {
  const listings = await fetchListings({ bypassCache: true });
  const details = await Promise.all(
    listings.map((listing) => fetchListingDetail(listing.id, publicKey)),
  );

  return details.flatMap((detail) => {
    const bids = detail.bids.filter(
      (bid) => bid.bidder_public_key === publicKey,
    );
    if (bids.length === 0) return [];

    const highestBid = Math.max(...detail.bids.map((bid) => Number(bid.bid_amount)));
    return bids.map((bid) => ({
      listingId: detail.listing.id,
      username: detail.listing.username,
      myBid: Number(bid.bid_amount),
      currentBid: highestBid,
      endsAt: new Date(detail.listing.created_at),
      isWinning: bid.status === "pending" && Number(bid.bid_amount) >= highestBid,
      status: bid.status,
    }));
  });
}

export async function fetchUserListings(publicKey = resolvePublicKey()): Promise<UserListing[]> {
  const listings = await fetchListings({ bypassCache: true });
  return listings
    .filter((listing) => listing.ownerAddress === formatPublicKey(publicKey))
    .map((listing) => ({
      username: listing.username,
      minBid: listing.currentBid,
      currentBid: listing.currentBid,
      bidCount: listing.bidCount,
      endsAt: listing.endsAt,
    }));
}

export type BidResult = { success: true } | { success: false; reason: string };

export type BackendListingStatus = "active" | "sold" | "cancelled";

export type BackendMarketplaceListing = {
  id: string;
  username: string;
  seller_public_key: string;
  asking_price: number;
  status: BackendListingStatus;
  created_at: string;
  updated_at: string;
  sold_at: string | null;
  buyer_public_key: string | null;
  final_price: number | null;
};

export type BackendMarketplaceBid = {
  id: string;
  listing_id: string;
  bidder_public_key: string;
  bid_amount: number;
  status: "pending" | "accepted" | "rejected" | "cancelled";
  created_at: string;
  updated_at: string;
};

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
  listing: BackendMarketplaceListing;
  bids: BackendMarketplaceBid[];
  seller: MarketplaceSellerInfo;
  state_hints: MarketplaceStateHints;
};

export class ListingDetailNotFoundError extends Error {
  constructor(listingId: string) {
    super(`Listing ${listingId} was not found.`);
    this.name = "ListingDetailNotFoundError";
  }
}

export async function fetchListingDetail(
  listingId: string,
  viewerPublicKey?: string,
): Promise<MarketplaceListingDetail> {
  const url = new URL(`${getQuickexApiBase()}/marketplace/${listingId}/detail`);
  if (viewerPublicKey?.trim()) {
    url.searchParams.set("viewerPublicKey", viewerPublicKey.trim());
  }

  const response = await fetch(url.toString(), {
    method: "GET",
    headers: { Accept: "application/json" },
  });

  if (response.status === 404) {
    throw new ListingDetailNotFoundError(listingId);
  }

  if (!response.ok) {
    throw new Error(`Failed to load listing detail (${response.status}).`);
  }

  return (await response.json()) as MarketplaceListingDetail;
}

export function mapListingDetailToCardListing(
  detail: MarketplaceListingDetail,
): MarketplaceListing {
  const { listing, bids, seller, state_hints } = detail;
  const currentBid = Math.max(state_hints.minimum_bid_amount - 1, Number(listing.asking_price));
  const pendingBidCount = bids.filter((bid) => bid.status === "pending").length;
  const createdAt = new Date(listing.created_at);

  const status: UsernameStatus =
    listing.status === "active"
      ? "auction"
      : listing.status === "sold"
        ? "sold"
        : "listed";

  return {
    id: listing.id,
    username: listing.username,
    currentBid,
    buyNowPrice: null,
    ownerAddress: seller.display_key,
    endsAt: createdAt,
    createdAt,
    status,
    category: "trending",
    bidCount: pendingBidCount,
    watchers: 0,
    verified: false,
  };
}

export function formatPublicKey(publicKey: string): string {
  if (publicKey.length <= 12) {
    return publicKey;
  }
  return `${publicKey.slice(0, 4)}...${publicKey.slice(-4)}`;
}

export async function placeBid(
  listingId: string,
  amount: number,
  bidderPublicKey = resolvePublicKey(),
): Promise<BidResult> {
  const response = await fetch(`${getQuickexApiBase()}/marketplace/${listingId}/bid`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({ bidderPublicKey, bidAmount: amount }),
  });
  const payload = (await response.json().catch(() => ({}))) as { message?: string };
  if (!response.ok) {
    return { success: false, reason: payload.message ?? `Bid failed (${response.status}).` };
  }
  return { success: true };
}

export async function acceptBid(
  listingId: string,
  bidId: string,
  sellerPublicKey = resolvePublicKey(),
): Promise<BidResult> {
  const response = await fetch(
    `${getQuickexApiBase()}/marketplace/${listingId}/accept-bid/${bidId}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ sellerPublicKey }),
    },
  );
  const payload = (await response.json().catch(() => ({}))) as { message?: string };
  if (!response.ok) {
    return { success: false, reason: payload.message ?? `Accepting bid failed (${response.status}).` };
  }
  return { success: true };
}

export function formatCountdown(date: Date): string {
  const diff = date.getTime() - Date.now();
  if (diff <= 0) return "Ended";
  const h = Math.floor(diff / 3600000);
  const m = Math.floor((diff % 3600000) / 60000);
  if (h >= 24) return `${Math.floor(h / 24)}d ${h % 24}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}
