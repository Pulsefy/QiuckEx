// Marketplace API client. Listings come from the backend; user bids and
// user listings are still mocked pending backend endpoints.

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

const HOUR = 3600000;

// NOTE: Mock data for endpoints that do not have a backend yet.
// If your original MOCK_USER_BIDS / MOCK_USER_LISTINGS exist on origin/main,
// paste those over these two arrays to keep the dashboard data identical.
const MOCK_USER_BIDS: UserBid[] = [
  {
    username: "satoshi",
    myBid: 850,
    currentBid: 850,
    endsAt: new Date(Date.now() + 5 * HOUR),
    isWinning: true,
  },
  {
    username: "stellar",
    myBid: 600,
    currentBid: 720,
    endsAt: new Date(Date.now() + 26 * HOUR),
    isWinning: false,
  },
];

const MOCK_USER_LISTINGS: UserListing[] = [
  {
    username: "quickex",
    minBid: 100,
    currentBid: 240,
    bidCount: 6,
    endsAt: new Date(Date.now() + 48 * HOUR),
  },
  {
    username: "pay",
    minBid: 500,
    currentBid: 500,
    bidCount: 0,
    endsAt: new Date(Date.now() + 72 * HOUR),
  },
];

let cachedListings: MarketplaceListing[] | null = null;
let cachedUserBids: UserBid[] | null = null;
let cachedUserListings: UserListing[] | null = null;

export type FetchListingsOptions = {
  limit?: number;
  cursor?: string;
  bypassCache?: boolean;
};

export interface FetchListingsResponse {
  listings: MarketplaceListing[];
  /** True when the backend request failed, so `listings` is empty and not real data */
  degraded: boolean;
}

export async function fetchListings(
  options: FetchListingsOptions = {},
): Promise<FetchListingsResponse> {
  const { limit = 100, cursor, bypassCache = false } = options;

  if (!bypassCache && cachedListings) {
    return { listings: cachedListings, degraded: false };
  }

  try {
    const url = new URL(`${getQuickexApiBase()}/marketplace`);
    url.searchParams.set("limit", limit.toString());
    if (cursor) {
      url.searchParams.set("cursor", cursor);
    }

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

    const mapped = (data.listings ?? []).map(mapBackendListingToCardListing);
    cachedListings = mapped;
    return { listings: mapped, degraded: false };
  } catch (err) {
    console.warn("Marketplace backend query error, returning empty list:", err);
    return { listings: [], degraded: true };
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

export type BidErrorCode =
  | "network"
  | "validation"
  | "insufficient_funds"
  | "unauthorized"
  | "not_found"
  | "conflict"
  | "unknown";

export type BidResult =
  | { success: true; bid?: BackendMarketplaceBid }
  | { success: false; reason: string; code?: BidErrorCode; details?: string };

export type PlaceBidOptions = {
  listingId?: string;
  bidderPublicKey?: string;
};

function getStoredWalletPublicKey(): string | null {
  if (typeof window === "undefined") return null;
  try {
    const raw = localStorage.getItem("quickex.wallet.session");
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    return typeof parsed?.publicKey === "string" ? parsed.publicKey : null;
  } catch {
    return null;
  }
}

const DEFAULT_DEMO_BIDDER_KEY = "GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR";

export async function placeBid(
  usernameOrListingId: string,
  amount: number,
  options?: PlaceBidOptions
): Promise<BidResult> {
  let resolvedListingId = options?.listingId;

  if (!resolvedListingId) {
    if (cachedListings) {
      const matchById = cachedListings.find((item) => item.id === usernameOrListingId);
      if (matchById) {
        resolvedListingId = matchById.id;
      } else {
        const matchByUsername = cachedListings.find(
          (item) => item.username.toLowerCase() === usernameOrListingId.toLowerCase()
        );
        if (matchByUsername) {
          resolvedListingId = matchByUsername.id;
        }
      }
    }
  }

  if (!resolvedListingId) {
    resolvedListingId = usernameOrListingId;
  }

  const bidderPublicKey =
    options?.bidderPublicKey?.trim() ||
    getStoredWalletPublicKey() ||
    DEFAULT_DEMO_BIDDER_KEY;

  const url = `${getQuickexApiBase()}/marketplace/${encodeURIComponent(resolvedListingId)}/bid`;

  try {
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({
        bidderPublicKey,
        bidAmount: amount,
      }),
    });

    if (response.ok) {
      const data = (await response.json().catch(() => ({}))) as { bid?: BackendMarketplaceBid };
      return {
        success: true,
        bid: data.bid,
      };
    }

    const errorData = await response.json().catch(() => null);
    let rawReason = "";
    if (errorData) {
      if (Array.isArray(errorData.message)) {
        rawReason = errorData.message.join(", ");
      } else if (typeof errorData.message === "string") {
        rawReason = errorData.message;
      } else if (typeof errorData.error === "string") {
        rawReason = errorData.error;
      }
    }

    if (!rawReason) {
      rawReason = `Failed to place bid (${response.status} ${response.statusText || ""})`.trim();
    }

    const lower = rawReason.toLowerCase();
    let code: BidErrorCode = "unknown";

    if (
      response.status === 402 ||
      lower.includes("insufficient") ||
      lower.includes("balance") ||
      lower.includes("funds")
    ) {
      code = "insufficient_funds";
    } else if (
      response.status === 400 ||
      response.status === 422 ||
      lower.includes("invalid") ||
      lower.includes("must be") ||
      lower.includes("seller cannot bid") ||
      errorData?.code === "MARKETPLACE_INVALID_PRICE" ||
      errorData?.code === "MARKETPLACE_SELF_BID"
    ) {
      code = "validation";
    } else if (response.status === 401 || response.status === 403 || errorData?.code === "MARKETPLACE_UNAUTHORIZED") {
      code = "unauthorized";
    } else if (response.status === 404 || errorData?.code === "LISTING_NOT_FOUND") {
      code = "not_found";
    } else if (response.status === 409 || errorData?.code === "USERNAME_ALREADY_LISTED" || errorData?.code === "LISTING_NOT_ACTIVE") {
      code = "conflict";
    } else if (response.status >= 500) {
      code = "network";
    }

    return {
      success: false,
      reason: rawReason,
      code,
    };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Failed to connect to the marketplace service.";
    return {
      success: false,
      reason: message,
      code: "network",
    };
  }
}

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

// NOTE: Reconstructed because it was missing from the pasted file. If your
// original exists on origin/main, prefer that one so field mapping is identical.
function mapBackendListingToCardListing(
  listing: BackendMarketplaceListing,
): MarketplaceListing {
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
    currentBid: Number(listing.asking_price),
    buyNowPrice: null,
    ownerAddress: formatPublicKey(listing.seller_public_key),
    endsAt: createdAt,
    createdAt,
    status,
    category: "trending",
    bidCount: 0,
    watchers: 0,
    verified: false,
  };
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


export function formatCountdown(date: Date): string {
  const diff = date.getTime() - Date.now();
  if (diff <= 0) return "Ended";
  const h = Math.floor(diff / 3600000);
  const m = Math.floor((diff % 3600000) / 60000);
  if (h >= 24) return `${Math.floor(h / 24)}d ${h % 24}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}