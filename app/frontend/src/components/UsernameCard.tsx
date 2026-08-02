"use client";

import { MarketplaceListing, formatCountdown } from "@/hooks/marketplaceApi";
import { useWatchlist } from "@/contexts/WatchlistContext";

type UsernameCardProps = {
  listing: MarketplaceListing;
  onBid: (listing: MarketplaceListing) => void;
  onViewDetails: (listing: MarketplaceListing) => void;
};

const CATEGORY_LABELS: Record<MarketplaceListing["category"], string> = {
  trending: "🔥 Trending",
  short: "⚡ Short",
  og: "💎 OG",
  crypto: "₿ Crypto",
  brand: "✦ Brand",
};

const CATEGORY_COLORS: Record<MarketplaceListing["category"], string> = {
  trending: "text-orange-400 bg-orange-400/10 border-orange-400/20",
  short: "text-yellow-400 bg-yellow-400/10 border-yellow-400/20",
  og: "text-purple-400 bg-purple-400/10 border-purple-400/20",
  crypto: "text-indigo-400 bg-indigo-400/10 border-indigo-400/20",
  brand: "text-teal-400 bg-teal-400/10 border-teal-400/20",
};

function UrgencyBar({ endsAt }: { endsAt: Date }) {
  const total = 7 * 24 * 3600 * 1000; // 7 day auction window
  const remaining = Math.max(0, endsAt.getTime() - Date.now());
  const pct = Math.min(100, Math.round((remaining / total) * 100));
  const color =
    pct < 15
      ? "bg-red-500"
      : pct < 40
      ? "bg-amber-500"
      : "bg-indigo-500";

  return (
    <div className="w-full h-[3px] bg-surface rounded-full overflow-hidden">
      <div
        className={`h-full rounded-full ${color} transition-all duration-1000`}
        style={{ width: `${pct}%` }}
      />
    </div>
  );
}

export function UsernameCard({ listing, onBid, onViewDetails }: UsernameCardProps) {
  const { isInWatchlist, toggleWatchlist } = useWatchlist();
  const catColor = CATEGORY_COLORS[listing.category];
  const catLabel = CATEGORY_LABELS[listing.category];
  const countdown = formatCountdown(listing.endsAt);
  const isUrgent = listing.endsAt.getTime() - Date.now() < 1000 * 60 * 90;
  const isWatched = isInWatchlist(listing.id);

  const handleWatchlistClick = (e: React.MouseEvent) => {
    e.stopPropagation();
    toggleWatchlist(listing.id, listing.username);
  };

  return (
    <div className="group relative flex flex-col bg-card/50 border border-border rounded-3xl overflow-hidden hover:border-indigo-500/30 transition-all duration-300 hover:shadow-[0_0_40px_-15px_rgba(99,102,241,0.25)] hover:-translate-y-1">
      {/* Top glow strip */}
      <div className="h-[2px] w-full bg-gradient-to-r from-indigo-500/0 via-indigo-500/60 to-indigo-500/0 opacity-0 group-hover:opacity-100 transition-opacity duration-500" />

      <div className="p-6 flex flex-col flex-1 gap-4">
        {/* Top row: category + verified + watchlist */}
        <div className="flex items-center justify-between">
          <span
            className={`text-[10px] font-black uppercase tracking-widest px-2 py-1 rounded-lg border ${catColor}`}
          >
            {catLabel}
          </span>
          <div className="flex items-center gap-2">
            {listing.verified && (
              <span
                title="Verified"
                className="text-[10px] font-black text-emerald-400 bg-emerald-400/10 border border-emerald-400/20 px-2 py-1 rounded-lg"
              >
                ✓ Verified
              </span>
            )}
            <button
              onClick={handleWatchlistClick}
              className={`w-8 h-8 rounded-full flex items-center justify-center transition-all duration-200 ${
                isWatched
                  ? 'bg-red-500/20 border border-red-500/30 text-red-400 hover:bg-red-500/30'
                  : 'bg-surface border border-border-strong text-subtle hover:text-red-400 hover:bg-red-500/10'
              }`}
              title={isWatched ? 'Remove from watchlist' : 'Add to watchlist'}
            >
              {isWatched ? '❤️' : '🤍'}
            </button>
          </div>
        </div>

        {/* Username */}
        <div className="flex-1">
          <p className="text-xs text-faint font-mono mb-0.5">quickex.to/</p>
          <h3 className="text-3xl font-black tracking-tight text-foreground leading-none group-hover:text-brand transition-colors duration-300">
            {listing.username}
          </h3>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-2 gap-2">
          <div className="p-3 rounded-2xl bg-surface border border-border">
            <p className="text-[9px] uppercase font-black tracking-widest text-faint mb-1">
              Current Bid
            </p>
            <p className="font-black text-base text-foreground leading-none">
              {listing.currentBid.toLocaleString()}
              <span className="text-[10px] font-bold text-subtle ml-1">USDC</span>
            </p>
          </div>
          <div className="p-3 rounded-2xl bg-surface border border-border">
            <p className="text-[9px] uppercase font-black tracking-widest text-faint mb-1">
              Ends In
            </p>
            <p
              className={`font-black text-base leading-none ${
                isUrgent ? "text-red-400 animate-pulse" : "text-foreground"
              }`}
            >
              {countdown}
            </p>
          </div>
        </div>

        <UrgencyBar endsAt={listing.endsAt} />

        {/* Bottom row: owner + bid count */}
        <div className="flex items-center justify-between text-[11px] text-faint">
          <span className="font-mono">
            {listing.ownerAddress}
          </span>
          <span className="font-bold">
            {listing.bidCount} bids · {listing.watchers} watching
          </span>
        </div>

        {/* Buy now price */}
        {listing.buyNowPrice && (
          <p className="text-[10px] text-subtle -mt-2">
            Buy Now:{" "}
            <span className="text-foreground font-bold">
              {listing.buyNowPrice.toLocaleString()} USDC
            </span>
          </p>
        )}

        <div className="mt-auto grid grid-cols-2 gap-2">
          <button
            type="button"
            onClick={() => onViewDetails(listing)}
            className="w-full rounded-2xl border border-border-strong bg-surface py-3.5 text-sm font-bold tracking-wide text-foreground transition-all duration-200 hover:bg-surface-strong"
          >
            View Details
          </button>
          <button
            id={`bid-btn-${listing.id}`}
            type="button"
            onClick={() => onBid(listing)}
            className="w-full rounded-2xl border border-indigo-500/30 bg-indigo-500/10 py-3.5 text-sm font-black tracking-wide text-brand transition-all duration-200 hover:border-indigo-500 hover:bg-indigo-500 hover:text-white hover:shadow-[0_8px_32px_-10px_rgba(99,102,241,0.6)] active:scale-95"
          >
            Place Bid
          </button>
        </div>
      </div>
    </div>
  );
}
