"use client";

import { useEffect, useState } from "react";
import {
  fetchListingDetail,
  formatPublicKey,
  ListingDetailNotFoundError,
  mapListingDetailToCardListing,
  MarketplaceListing,
  MarketplaceListingDetail,
} from "@/hooks/marketplaceApi";

type ListingDetailModalProps = {
  listingId: string | null;
  viewerPublicKey?: string | null;
  isWatched: boolean;
  onClose: () => void;
  onToggleWatchlist: (listing: MarketplaceListing) => void;
  onPlaceBid: (listing: MarketplaceListing) => void;
};

type DetailLoadState =
  | { kind: "idle" }
  | { kind: "loading" }
  | { kind: "missing" }
  | { kind: "error"; message: string }
  | { kind: "ready"; detail: MarketplaceListingDetail };

const STATUS_LABELS: Record<MarketplaceListingDetail["listing"]["status"], string> = {
  active: "Active",
  sold: "Sold",
  cancelled: "Unavailable",
};

function formatBidStatus(status: MarketplaceListingDetail["bids"][number]["status"]): string {
  return status.charAt(0).toUpperCase() + status.slice(1);
}

export function ListingDetailModal({
  listingId,
  viewerPublicKey,
  isWatched,
  onClose,
  onToggleWatchlist,
  onPlaceBid,
}: ListingDetailModalProps) {
  const [loadState, setLoadState] = useState<DetailLoadState>({ kind: "idle" });

  useEffect(() => {
    if (!listingId) {
      setLoadState({ kind: "idle" });
      return;
    }

    let cancelled = false;
    setLoadState({ kind: "loading" });

    fetchListingDetail(listingId, viewerPublicKey ?? undefined)
      .then((detail) => {
        if (!cancelled) {
          setLoadState({ kind: "ready", detail });
        }
      })
      .catch((error: unknown) => {
        if (cancelled) {
          return;
        }
        if (error instanceof ListingDetailNotFoundError) {
          setLoadState({ kind: "missing" });
          return;
        }
        const message =
          error instanceof Error && error.message
            ? error.message
            : "Unable to load listing detail.";
        setLoadState({ kind: "error", message });
      });

    return () => {
      cancelled = true;
    };
  }, [listingId, viewerPublicKey]);

  if (!listingId || loadState.kind === "idle") {
    return null;
  }

  const cardListing =
    loadState.kind === "ready"
      ? mapListingDetailToCardListing(loadState.detail)
      : null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-background/75 backdrop-blur-md" onClick={onClose} />

      <div className="relative z-10 w-full max-w-4xl overflow-hidden rounded-[32px] border border-border-strong bg-background/90 shadow-2xl">
        {loadState.kind === "loading" && (
          <div className="p-10 text-center">
            <p className="text-sm font-semibold text-subtle">Loading listing detail…</p>
          </div>
        )}

        {loadState.kind === "missing" && (
          <div className="space-y-4 p-10 text-center">
            <p className="text-xs font-black uppercase tracking-[0.3em] text-brand">Unavailable</p>
            <h2 className="text-2xl font-black text-foreground">Listing not found</h2>
            <p className="text-sm text-subtle">
              This listing may have been removed or the link is no longer valid.
            </p>
            <button
              type="button"
              onClick={onClose}
              className="rounded-2xl bg-surface px-4 py-3 text-sm font-bold text-foreground transition hover:bg-surface-strong"
            >
              Close
            </button>
          </div>
        )}

        {loadState.kind === "error" && (
          <div className="space-y-4 p-10 text-center">
            <p className="text-xs font-black uppercase tracking-[0.3em] text-danger">Error</p>
            <h2 className="text-2xl font-black text-foreground">Could not load listing</h2>
            <p className="text-sm text-subtle">{loadState.message}</p>
            <button
              type="button"
              onClick={onClose}
              className="rounded-2xl bg-surface px-4 py-3 text-sm font-bold text-foreground transition hover:bg-surface-strong"
            >
              Close
            </button>
          </div>
        )}

        {loadState.kind === "ready" && cardListing && (
          <div className="grid gap-0 lg:grid-cols-[1.1fr_0.9fr]">
            <section className="border-b border-border-strong p-8 lg:border-b-0 lg:border-r">
              <div className="flex items-start justify-between gap-4">
                <div>
                  <p className="text-xs font-black uppercase tracking-[0.3em] text-brand">
                    Listing Detail
                  </p>
                  <h2 className="mt-3 text-4xl font-black text-foreground">
                    @{loadState.detail.listing.username}
                  </h2>
                  <p className="mt-3 max-w-xl text-sm leading-6 text-subtle">
                    Live marketplace data from the QuickEx backend, including seller info and bid
                    history for this username listing.
                  </p>
                </div>
                <button
                  type="button"
                  onClick={onClose}
                  className="flex h-10 w-10 items-center justify-center rounded-full border border-border-strong bg-surface text-muted transition hover:bg-surface-strong hover:text-foreground"
                >
                  ✕
                </button>
              </div>

              {!loadState.detail.state_hints.is_available && (
                <div className="mt-6 rounded-2xl border border-amber-400/20 bg-warning-soft p-4">
                  <p className="text-sm font-semibold text-foreground">Listing unavailable</p>
                  <p className="mt-1 text-xs leading-5 text-warning/80">
                    {loadState.detail.state_hints.unavailable_reason ??
                      "This listing is no longer accepting bids."}
                  </p>
                </div>
              )}

              <div className="mt-8 grid gap-4 sm:grid-cols-2">
                <div className="rounded-3xl border border-border-strong bg-surface p-5">
                  <p className="text-[10px] font-black uppercase tracking-[0.25em] text-subtle">
                    Current High Bid
                  </p>
                  <p className="mt-3 text-3xl font-black text-foreground">
                    {Math.max(
                      loadState.detail.state_hints.minimum_bid_amount - 1,
                      Number(loadState.detail.listing.asking_price),
                    ).toLocaleString()}{" "}
                    <span className="text-base text-subtle">USDC</span>
                  </p>
                  <p className="mt-2 text-xs text-subtle">
                    Minimum next bid:{" "}
                    {loadState.detail.state_hints.minimum_bid_amount.toLocaleString()} USDC
                  </p>
                </div>
                <div className="rounded-3xl border border-border-strong bg-surface p-5">
                  <p className="text-[10px] font-black uppercase tracking-[0.25em] text-subtle">
                    Status
                  </p>
                  <p className="mt-3 text-3xl font-black text-foreground">
                    {STATUS_LABELS[loadState.detail.listing.status]}
                  </p>
                  <p className="mt-2 text-xs text-subtle">
                    Listed {new Date(loadState.detail.listing.created_at).toLocaleString()}
                  </p>
                </div>
              </div>

              <div className="mt-6 grid gap-4 md:grid-cols-3">
                {[
                  {
                    label: "Asking Price",
                    value: `${Number(loadState.detail.listing.asking_price).toLocaleString()} USDC`,
                  },
                  {
                    label: "Bid Count",
                    value: loadState.detail.bids.length.toLocaleString(),
                  },
                  {
                    label: "Seller",
                    value: loadState.detail.seller.display_key,
                  },
                ].map((item) => (
                  <div key={item.label} className="rounded-2xl border border-border-strong bg-card p-4">
                    <p className="text-[10px] font-black uppercase tracking-[0.2em] text-subtle">
                      {item.label}
                    </p>
                    <p className="mt-2 text-sm font-semibold text-foreground">{item.value}</p>
                  </div>
                ))}
              </div>

              <div className="mt-8 rounded-[28px] border border-border-strong bg-surface p-5">
                <p className="text-xs font-black uppercase tracking-[0.25em] text-subtle">
                  Seller Info
                </p>
                <p className="mt-3 text-sm font-semibold text-foreground">
                  {loadState.detail.seller.display_key}
                </p>
                <p className="mt-1 break-all font-mono text-xs text-subtle">
                  {loadState.detail.seller.public_key}
                </p>
              </div>

              <div className="mt-6 rounded-[28px] border border-border-strong bg-card p-5">
                <p className="text-xs font-black uppercase tracking-[0.25em] text-subtle">
                  Bid History
                </p>
                {loadState.detail.bids.length === 0 ? (
                  <p className="mt-4 text-sm text-subtle">No bids yet. Be the first to bid.</p>
                ) : (
                  <ul className="mt-4 max-h-56 space-y-3 overflow-y-auto">
                    {loadState.detail.bids.map((bid) => (
                      <li
                        key={bid.id}
                        className="flex items-center justify-between rounded-2xl border border-border-strong bg-surface px-4 py-3 text-sm"
                      >
                        <div>
                          <p className="font-semibold text-foreground">
                            {Number(bid.bid_amount).toLocaleString()} USDC
                          </p>
                          <p className="text-xs text-subtle">
                            {formatPublicKey(bid.bidder_public_key)} ·{" "}
                            {new Date(bid.created_at).toLocaleString()}
                          </p>
                        </div>
                        <span className="text-xs font-bold uppercase tracking-wide text-subtle">
                          {formatBidStatus(bid.status)}
                        </span>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </section>

            <aside className="p-8">
              <div className="rounded-[28px] border border-border-strong bg-surface p-5">
                <p className="text-xs font-black uppercase tracking-[0.25em] text-subtle">
                  Actions
                </p>
                <div className="mt-5 space-y-4">
                  <div className="rounded-2xl border border-border-strong bg-card p-4">
                    <p className="text-sm font-semibold text-foreground">Backend availability</p>
                    <p className="mt-1 text-xs leading-5 text-subtle">
                      {loadState.detail.state_hints.can_place_bid
                        ? "You can place a bid on this listing."
                        : loadState.detail.state_hints.unavailable_reason ??
                          "Bidding is disabled for this listing."}
                    </p>
                  </div>
                  <div className="rounded-2xl border border-border-strong bg-card p-4">
                    <p className="text-sm font-semibold text-foreground">Watchlist status</p>
                    <p className="mt-1 text-xs leading-5 text-subtle">
                      {isWatched
                        ? "This listing is already saved to your watchlist."
                        : "Save this listing to revisit it quickly later."}
                    </p>
                  </div>
                </div>
              </div>

              <div className="mt-6 flex flex-col gap-3">
                <button
                  type="button"
                  disabled={!loadState.detail.state_hints.can_watchlist}
                  onClick={() => onToggleWatchlist(cardListing)}
                  className={`rounded-2xl border px-4 py-3 text-sm font-bold transition ${
                    !loadState.detail.state_hints.can_watchlist
                      ? "cursor-not-allowed border-border-strong bg-surface text-faint"
                      : isWatched
                        ? "border-red-400/30 bg-red-500/15 text-danger hover:bg-red-500/20"
                        : "border-border-strong bg-surface text-foreground hover:bg-surface-strong"
                  }`}
                >
                  {isWatched ? "Remove from watchlist" : "Add to watchlist"}
                </button>
                <button
                  type="button"
                  disabled={!loadState.detail.state_hints.can_place_bid}
                  onClick={() => onPlaceBid(cardListing)}
                  className={`rounded-2xl px-4 py-3 text-sm font-black transition ${
                    loadState.detail.state_hints.can_place_bid
                      ? "bg-indigo-500 text-white hover:bg-indigo-400"
                      : "cursor-not-allowed bg-surface text-faint"
                  }`}
                >
                  Continue to bid
                </button>
              </div>
            </aside>
          </div>
        )}
      </div>
    </div>
  );
}
