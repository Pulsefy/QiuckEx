import { getQuickexApiBase } from "@/lib/api";
import { resolvePublicKey } from "@/lib/publicKey";

/**
 * Activity feed item as displayed in the dashboard.
 * Mirrors fields from the backend TransactionItemDto.
 */
export interface ActivityFeedItem {
  id: string;
  amount: string;
  asset: string;
  memo: string | null;
  date: string;
  status: "Settled" | "Pending";
  source: string;
  destination: string;
  timestamp: string; // raw ISO for sorting
}

interface BackendTransactionItem {
  amount: string;
  asset: string;
  memo?: string;
  timestamp: string;
  source: string;
  destination: string;
  status: "Success" | "Pending";
  txHash: string;
  pagingToken: string;
}

interface BackendResponse {
  items: BackendTransactionItem[];
}

function simplifyAsset(asset: string): string {
  const colonIdx = asset.indexOf(":");
  return colonIdx > -1 ? asset.slice(0, colonIdx) : asset;
}

function formatTimestamp(iso: string): string {
  try {
    const date = new Date(iso);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);

    if (diffMins < 1) return "Just now";
    if (diffMins < 60) return `${diffMins} min ago`;

    const diffHours = Math.floor(diffMins / 60);
    if (diffHours < 24) return `${diffHours}h ago`;

    const diffDays = Math.floor(diffHours / 24);
    if (diffDays < 7) return `${diffDays}d ago`;

    return date.toLocaleDateString("en-US", {
      month: "short",
      day: "numeric",
    });
  } catch {
    return iso;
  }
}

function mapToActivityItem(item: BackendTransactionItem): ActivityFeedItem {
  return {
    id: item.txHash,
    amount: item.amount,
    asset: simplifyAsset(item.asset),
    memo: item.memo ?? null,
    date: formatTimestamp(item.timestamp),
    status: item.status === "Success" ? "Settled" : "Pending",
    source: item.source,
    destination: item.destination,
    timestamp: item.timestamp,
  };
}

export interface ActivityFeedResponse {
  items: ActivityFeedItem[];
  /** True when the backend returned no data or the request failed gracefully */
  degraded: boolean;
}

/**
 * Fetch the dashboard activity feed from the backend.
 * Falls back to an empty list on failure with `degraded: true`.
 */
export async function fetchActivityFeed(
  limit = 20,
): Promise<ActivityFeedResponse> {
  const publicKey = resolvePublicKey();
  const url = new URL(`${getQuickexApiBase()}/payments/recent`);
  url.searchParams.set("address", publicKey);
  url.searchParams.set("limit", String(limit));

  try {
    const res = await fetch(url.toString(), { method: "GET" });

    if (!res.ok) {
      if (res.status >= 400 && res.status < 500) {
        // Client error (e.g. bad public key) — return empty, not degraded
        console.warn(
          `Activity feed: client error ${res.status}, returning empty list`,
        );
        return { items: [], degraded: false };
      }
      throw new Error(
        `Activity feed request failed with status ${res.status}`,
      );
    }

    const data = (await res.json()) as BackendResponse;
    return {
      items: (data.items ?? []).map(mapToActivityItem),
      degraded: false,
    };
  } catch (error) {
    console.warn("Activity feed: backend unavailable, returning empty list:", error);
    return { items: [], degraded: true };
  }
}
