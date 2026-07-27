// Marketplace mock data and simulated API calls

import { getQuickexApiBase } from "@/lib/api";
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
  username: string;
  myBid: number;
  currentBid: number;
  endsAt: Date;
  isWinning: boolean;
};

export type UserListing = {
  username: string;
  minBid: number;
  currentBid: number;
  bidCount: number;
  endsAt: Date;
};

let cachedListings: MarketplaceListing[] | null = null;
let cachedUserBids: UserBid[] | null = null;
let cachedUserListings: UserListing[] | null = null;

const MOCK_LISTINGS: MarketplaceListing[] = [
  {
    id: "1",
    username: "pay",
    currentBid: 5800,
    buyNowPrice: 12000,
    ownerAddress: "GDRH...4T9F",
    endsAt: new Date(Date.now() + 1000 * 60 * 60 * 2.5),
    createdAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 2), // 2 days ago
    status: "auction",
    category: "og",
    bidCount: 34,
    watchers: 210,
    verified: true,
  },
  {
    id: "2",
    username: "sol",
    currentBid: 3200,
    buyNowPrice: 8500,
    ownerAddress: "GCXY...8K3J",
    endsAt: new Date(Date.now() + 1000 * 60 * 60 * 5),
    createdAt: new Date(Date.now() - 1000 * 60 * 60 * 12), // 12 hours ago
    status: "auction",
    category: "crypto",
    bidCount: 19,
    watchers: 98,
    verified: true,
  },
  {
    id: "3",
    username: "nova",
    currentBid: 1400,
    buyNowPrice: 4000,
    ownerAddress: "GBXT...2R7K",
    endsAt: new Date(Date.now() + 1000 * 60 * 60 * 24),
    createdAt: new Date(Date.now() - 1000 * 60 * 60 * 6), // 6 hours ago
    status: "auction",
    category: "brand",
    bidCount: 8,
    watchers: 54,
    verified: false,
  },
  {
    id: "4",
    username: "satoshi",
    currentBid: 9900,
    buyNowPrice: null,
    ownerAddress: "GDKL...5W1M",
    endsAt: new Date(Date.now() + 1000 * 60 * 47),
    createdAt: new Date(Date.now() - 1000 * 60 * 60 * 48), // 2 days ago
    status: "auction",
    category: "trending",
    bidCount: 62,
    watchers: 445,
    verified: true,
  },
  {
    id: "5",
    username: "alex",
    currentBid: 780,
    buyNowPrice: 2000,
    ownerAddress: "GCMQ...9P2N",
    endsAt: new Date(Date.now() + 1000 * 60 * 60 * 36),
    createdAt: new Date(Date.now() - 1000 * 60 * 30), // 30 minutes ago
    status: "auction",
    category: "short",
    bidCount: 5,
    watchers: 31,
    verified: false,
  },
  {
    id: "6",
    username: "defi",
    currentBid: 4100,
    buyNowPrice: null,
    ownerAddress: "GBKR...1Q0C",
    endsAt: new Date(Date.now() + 1000 * 60 * 60 * 12),
    createdAt: new Date(Date.now() - 1000 * 60 * 60 * 24), // 1 day ago
    status: "auction",
    category: "crypto",
    bidCount: 27,
    watchers: 182,
    verified: true,
  },
  {
    id: "7",
    username: "lux",
    currentBid: 620,
    buyNowPrice: 1500,
    ownerAddress: "GDXP...3F4G",
    endsAt: new Date(Date.now() + 1000 * 60 * 60 * 48),
    createdAt: new Date(Date.now() - 1000 * 60 * 15), // 15 minutes ago
    status: "listed",
    category: "brand",
    bidCount: 3,
    watchers: 22,
    verified: false,
  },
  {
    id: "8",
    username: "web3",
    currentBid: 2700,
    buyNowPrice: 6000,
    ownerAddress: "GBNH...7T5Q",
    endsAt: new Date(Date.now() + 1000 * 60 * 60 * 8),
    createdAt: new Date(Date.now() - 1000 * 60 * 60 * 3), // 3 hours ago
    status: "auction",
    category: "trending",
    bidCount: 15,
    watchers: 113,
    verified: true,
  },
];

const MOCK_USER_BIDS: UserBid[] = [
  {
    username: "nova",
    myBid: 1200,
    currentBid: 1400,
    endsAt: new Date(Date.now() + 1000 * 60 * 60 * 24),
    isWinning: false,
  },
  {
    username: "lux",
    myBid: 620,
    currentBid: 620,
    endsAt: new Date(Date.now() + 1000 * 60 * 60 * 48),
    isWinning: true,
  },
];

const MOCK_USER_LISTINGS: UserListing[] = [
  {
    username: "stellardev",
    minBid: 300,
    currentBid: 480,
    bidCount: 3,
    endsAt: new Date(Date.now() + 1000 * 60 * 60 * 72),
  },
];

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
    console.warn("Marketplace backend query error, returning fallback list:", err);
    cachedListings = MOCK_LISTINGS;
    return MOCK_LISTINGS;
  }
}

export async function fetchUserBids(): Promise<UserBid[]> {
  if (cachedUserBids) {
    return Promise.resolve(cachedUserBids);
  }

  return new Promise((resolve) =>
    setTimeout(() => {
      cachedUserBids = MOCK_USER_BIDS;
      resolve(MOCK_USER_BIDS);
    }, 700),
  );
}

export async function fetchUserListings(): Promise<UserListing[]> {
  if (cachedUserListings) {
    return Promise.resolve(cachedUserListings);
  }

  return new Promise((resolve) =>
    setTimeout(() => {
      cachedUserListings = MOCK_USER_LISTINGS;
      resolve(MOCK_USER_LISTINGS);
    }, 700),
  );
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
  username: string,
  amount: number
): Promise<BidResult> {
  return new Promise((resolve) => {
    setTimeout(() => {
      // Simulate ~10% chance of wallet rejection, otherwise success
      if (Math.random() < 0.1) {
        resolve({ success: false, reason: "User rejected the transaction in wallet." });
      } else {
        console.log(`Bid placed: ${amount} USDC on @${username}`);
        resolve({ success: true });
      }
    }, 2200);
  });
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
