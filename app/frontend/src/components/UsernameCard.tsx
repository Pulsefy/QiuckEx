"use client";

import { MarketplaceListing, formatCountdown } from "@/hooks/marketplaceApi";

type UsernameCardProps = {
  listing: MarketplaceListing;
  onBid: (listing: MarketplaceListing) => void;
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
    <div className="w-full h-[3px] bg-white/5 rounded-full overflow-hidden">
      <div
        className={`h-full rounded-full ${color} transition-all duration-1000`}
        style={{ width: `${pct}%` }}
      />
    </div>
  );
}

export function UsernameCard({ listing, onBid }: UsernameCardProps) {
  const catColor = CATEGORY_COLORS[listing.category];
  const catLabel = CATEGORY_LABELS[listing.category];
  const countdown = formatCountdown(listing.endsAt);
  const isUrgent = listing.endsAt.getTime() - Date.now() < 1000 * 60 * 90;

  return (
    <div className="group relative flex flex-col bg-neutral-900/50 border border-white/5 rounded-3xl overflow-hidden hover:border-indigo-500/30 transition-all duration-300 hover:shadow-[0_0_40px_-15px_rgba(99,102,241,0.25)] hover:-translate-y-1">
      {/* Top glow strip */}
      <div className="h-[2px] w-full bg-gradient-to-r from-indigo-500/0 via-indigo-500/60 to-indigo-500/0 opacity-0 group-hover:opacity-100 transition-opacity duration-500" />

      <div className="p-6 flex flex-col flex-1 gap-4">
        {/* Top row: category + verified */}
        <div className="flex items-center justify-between">
          <span
            className={`text-[10px] font-black uppercase tracking-widest px-2 py-1 rounded-lg border ${catColor}`}
          >
            {catLabel}
          </span>
          {listing.verified && (
            <span
              title="Verified"
              className="text-[10px] font-black text-emerald-400 bg-emerald-400/10 border border-emerald-400/20 px-2 py-1 rounded-lg"
            >
              ✓ Verified
            </span>
          )}
        </div>

        {/* Username */}
        <div className="flex-1">
          <p className="text-xs text-neutral-600 font-mono mb-0.5">quickex.to/</p>
          <h3 className="text-3xl font-black tracking-tight text-white leading-none group-hover:text-indigo-300 transition-colors duration-300">
            {listing.username}
          </h3>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-2 gap-2">
          <div className="p-3 rounded-2xl bg-white/[0.03] border border-white/5">
            <p className="text-[9px] uppercase font-black tracking-widest text-neutral-600 mb-1">
              Current Bid
            </p>
            <p className="font-black text-base text-white leading-none">
              {listing.currentBid.toLocaleString()}
              <span className="text-[10px] font-bold text-neutral-500 ml-1">USDC</span>
            </p>
          </div>
          <div className="p-3 rounded-2xl bg-white/[0.03] border border-white/5">
            <p className="text-[9px] uppercase font-black tracking-widest text-neutral-600 mb-1">
              Ends In
            </p>
            <p
              className={`font-black text-base leading-none ${
                isUrgent ? "text-red-400 animate-pulse" : "text-white"
              }`}
            >
              {countdown}
            </p>
          </div>
        </div>

        <UrgencyBar endsAt={listing.endsAt} />

        {/* Bottom row: owner + bid count */}
        <div className="flex items-center justify-between text-[11px] text-neutral-600">
          <span className="font-mono">
            {listing.ownerAddress}
          </span>
          <span className="font-bold">
            {listing.bidCount} bids · {listing.watchers} watching
          </span>
        </div>

        {/* Buy now price */}
        {listing.buyNowPrice && (
          <p className="text-[10px] text-neutral-500 -mt-2">
            Buy Now:{" "}
            <span className="text-white font-bold">
              {listing.buyNowPrice.toLocaleString()} USDC
            </span>
          </p>
        )}

        {/* CTA Button */}
        <button
          id={`bid-btn-${listing.id}`}
          onClick={() => onBid(listing)}
          className="mt-auto w-full py-3.5 bg-indigo-500/10 hover:bg-indigo-500 border border-indigo-500/30 hover:border-indigo-500 text-indigo-300 hover:text-white font-black rounded-2xl transition-all duration-200 hover:shadow-[0_8px_32px_-10px_rgba(99,102,241,0.6)] active:scale-95 text-sm tracking-wide"
        >
          Place Bid →
        </button>
      </div>
    </div>
  );
}
