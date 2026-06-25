"use client";

import { MarketplaceListing, formatCountdown } from "@/hooks/marketplaceApi";

type ListingDetailModalProps = {
  listing: MarketplaceListing | null;
  isWatched: boolean;
  onClose: () => void;
  onToggleWatchlist: (listing: MarketplaceListing) => void;
  onPlaceBid: (listing: MarketplaceListing) => void;
};

const CATEGORY_COPY: Record<MarketplaceListing["category"], string> = {
  brand: "Brand-ready handles with business-friendly naming.",
  crypto: "Crypto-native names that map well to wallets and trading profiles.",
  og: "Short, high-signal originals with premium scarcity.",
  short: "Compact handles that are easy to type and remember.",
  trending: "Popular names with the strongest current bidding velocity.",
};

export function ListingDetailModal({
  listing,
  isWatched,
  onClose,
  onToggleWatchlist,
  onPlaceBid,
}: ListingDetailModalProps) {
  if (!listing) {
    return null;
  }

  const minimumBid = listing.currentBid + 1;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-background/75 backdrop-blur-md" onClick={onClose} />

      <div className="relative z-10 w-full max-w-4xl overflow-hidden rounded-[32px] border border-border-strong bg-background/90 shadow-2xl">
        <div className="grid gap-0 lg:grid-cols-[1.1fr_0.9fr]">
          <section className="border-b border-border-strong p-8 lg:border-b-0 lg:border-r">
            <div className="flex items-start justify-between gap-4">
              <div>
                <p className="text-xs font-black uppercase tracking-[0.3em] text-brand">
                  Listing Detail
                </p>
                <h2 className="mt-3 text-4xl font-black text-foreground">@{listing.username}</h2>
                <p className="mt-3 max-w-xl text-sm leading-6 text-subtle">
                  {CATEGORY_COPY[listing.category]} This listing is receiving live auction updates while the marketplace connection stays active.
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

            <div className="mt-8 grid gap-4 sm:grid-cols-2">
              <div className="rounded-3xl border border-border-strong bg-surface p-5">
                <p className="text-[10px] font-black uppercase tracking-[0.25em] text-subtle">
                  Current Bid
                </p>
                <p className="mt-3 text-3xl font-black text-foreground">
                  {listing.currentBid.toLocaleString()} <span className="text-base text-subtle">USDC</span>
                </p>
                <p className="mt-2 text-xs text-subtle">
                  Minimum next bid: {minimumBid.toLocaleString()} USDC
                </p>
              </div>
              <div className="rounded-3xl border border-border-strong bg-surface p-5">
                <p className="text-[10px] font-black uppercase tracking-[0.25em] text-subtle">
                  Auction Clock
                </p>
                <p className="mt-3 text-3xl font-black text-foreground">{formatCountdown(listing.endsAt)}</p>
                <p className="mt-2 text-xs text-subtle">
                  Created {listing.createdAt.toLocaleDateString()} with live bid refresh enabled
                </p>
              </div>
            </div>

            <div className="mt-6 grid gap-4 md:grid-cols-3">
              {[
                { label: "Watchers", value: listing.watchers.toLocaleString() },
                { label: "Bid Count", value: listing.bidCount.toLocaleString() },
                { label: "Seller", value: listing.ownerAddress },
              ].map((item) => (
                <div key={item.label} className="rounded-2xl border border-border-strong bg-card p-4">
                  <p className="text-[10px] font-black uppercase tracking-[0.2em] text-subtle">
                    {item.label}
                  </p>
                  <p className="mt-2 text-sm font-semibold text-foreground">{item.value}</p>
                </div>
              ))}
            </div>

            <div className="mt-8 rounded-[28px] border border-indigo-400/20 bg-indigo-500/10 p-5">
              <p className="text-xs font-black uppercase tracking-[0.25em] text-brand">
                Bidding Rules
              </p>
              <ul className="mt-4 space-y-3 text-sm leading-6 text-brand/90">
                <li>Minimum increments start at 1 USDC above the current high bid.</li>
                <li>Winning bidders pay only the final amount they confirmed on-chain.</li>
                <li>Buy-now pricing, when present, ends the auction immediately for the first confirmed buyer.</li>
                <li>Watched listings stay one tap away so you can revisit auctions without searching again.</li>
              </ul>
            </div>
          </section>

          <aside className="p-8">
            <div className="rounded-[28px] border border-border-strong bg-surface p-5">
              <p className="text-xs font-black uppercase tracking-[0.25em] text-subtle">
                Live Activity Snapshot
              </p>
              <div className="mt-5 space-y-4">
                <div className="rounded-2xl border border-emerald-400/15 bg-success-soft p-4">
                  <p className="text-sm font-semibold text-foreground">Real-time updates connected</p>
                  <p className="mt-1 text-xs leading-5 text-success/80">
                    Bid counts and current price refresh automatically whenever listing activity arrives.
                  </p>
                </div>
                <div className="rounded-2xl border border-border-strong bg-card p-4">
                  <p className="text-sm font-semibold text-foreground">Watchlist status</p>
                  <p className="mt-1 text-xs leading-5 text-subtle">
                    {isWatched
                      ? "This listing is already saved to your watchlist."
                      : "Save this listing to your watchlist to revisit it quickly later."}
                  </p>
                </div>
                {listing.buyNowPrice && (
                  <div className="rounded-2xl border border-amber-400/15 bg-warning-soft p-4">
                    <p className="text-sm font-semibold text-foreground">Buy now available</p>
                    <p className="mt-1 text-xs leading-5 text-warning/80">
                      Immediate purchase price: {listing.buyNowPrice.toLocaleString()} USDC.
                    </p>
                  </div>
                )}
              </div>
            </div>

            <div className="mt-6 flex flex-col gap-3">
              <button
                type="button"
                onClick={() => onToggleWatchlist(listing)}
                className={`rounded-2xl border px-4 py-3 text-sm font-bold transition ${
                  isWatched
                    ? "border-red-400/30 bg-red-500/15 text-danger hover:bg-red-500/20"
                    : "border-border-strong bg-surface text-foreground hover:bg-surface-strong"
                }`}
              >
                {isWatched ? "Remove from watchlist" : "Add to watchlist"}
              </button>
              <button
                type="button"
                onClick={() => onPlaceBid(listing)}
                className="rounded-2xl bg-indigo-500 px-4 py-3 text-sm font-black text-white transition hover:bg-indigo-400"
              >
                Continue to bid
              </button>
            </div>
          </aside>
        </div>
      </div>
    </div>
  );
}
