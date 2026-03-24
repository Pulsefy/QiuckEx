"use client";

import { useState, useEffect, useMemo } from "react";
import { NetworkBadge } from "@/components/NetworkBadge";
import { UsernameCard } from "@/components/UsernameCard";
import { BidModal } from "@/components/BidModal";
import {
  fetchListings,
  MarketplaceListing,
} from "@/hooks/marketplaceApi";
import Link from "next/link";

type Category = "all" | "trending" | "short" | "og" | "crypto" | "brand";

const CATEGORIES: { key: Category; label: string; icon: string }[] = [
  { key: "all", label: "All", icon: "◈" },
  { key: "trending", label: "Trending", icon: "🔥" },
  { key: "og", label: "OG", icon: "💎" },
  { key: "short", label: "Short", icon: "⚡" },
  { key: "crypto", label: "Crypto", icon: "₿" },
  { key: "brand", label: "Brand", icon: "✦" },
];

const SORT_OPTIONS = [
  { key: "ending", label: "Ending Soon" },
  { key: "bid_desc", label: "Highest Bid" },
  { key: "bid_asc", label: "Lowest Bid" },
  { key: "bids", label: "Most Bids" },
];

function StatsBar({ listings }: { listings: MarketplaceListing[] }) {
  const totalVolume = listings.reduce((s, l) => s + l.currentBid, 0);
  const totalBids = listings.reduce((s, l) => s + l.bidCount, 0);
  const totalWatching = listings.reduce((s, l) => s + l.watchers, 0);

  return (
    <div className="grid grid-cols-3 gap-4 mb-10">
      {[
        { label: "Total Volume", value: `${totalVolume.toLocaleString()} USDC`, icon: "📈" },
        { label: "Active Bids", value: totalBids.toString(), icon: "⚡" },
        { label: "Watchers", value: totalWatching.toString(), icon: "👁" },
      ].map((s) => (
        <div
          key={s.label}
          className="p-5 rounded-2xl bg-white/[0.03] border border-white/5 flex items-center gap-4"
        >
          <span className="text-2xl opacity-70">{s.icon}</span>
          <div>
            <p className="text-[10px] uppercase font-black tracking-widest text-neutral-500 mb-0.5">
              {s.label}
            </p>
            <p className="font-black text-lg">{s.value}</p>
          </div>
        </div>
      ))}
    </div>
  );
}

export default function MarketplacePage() {
  const [listings, setListings] = useState<MarketplaceListing[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [activeCategory, setActiveCategory] = useState<Category>("all");
  const [sortKey, setSortKey] = useState("ending");
  const [activeListing, setActiveListing] = useState<MarketplaceListing | null>(null);

  useEffect(() => {
    fetchListings().then((data) => {
      setListings(data);
      setLoading(false);
    });
  }, []);

  function handleBidSuccess(username: string, amount: number) {
    setListings((prev) =>
      prev.map((l) =>
        l.username === username
          ? { ...l, currentBid: amount, bidCount: l.bidCount + 1 }
          : l
      )
    );
  }

  const filtered = useMemo(() => {
    let result = listings;

    if (activeCategory !== "all") {
      result = result.filter((l) => l.category === activeCategory);
    }

    if (search.trim()) {
      const q = search.toLowerCase().trim();
      result = result.filter((l) => l.username.includes(q));
    }

    switch (sortKey) {
      case "ending":
        result = [...result].sort((a, b) => a.endsAt.getTime() - b.endsAt.getTime());
        break;
      case "bid_desc":
        result = [...result].sort((a, b) => b.currentBid - a.currentBid);
        break;
      case "bid_asc":
        result = [...result].sort((a, b) => a.currentBid - b.currentBid);
        break;
      case "bids":
        result = [...result].sort((a, b) => b.bidCount - a.bidCount);
        break;
    }

    return result;
  }, [listings, search, activeCategory, sortKey]);

  return (
    <div className="relative min-h-screen text-white selection:bg-indigo-500/30">
      {/* Background auras */}
      <div className="fixed top-[-20%] right-[-20%] w-[55%] h-[55%] bg-indigo-500/8 blur-[140px] rounded-full pointer-events-none" />
      <div className="fixed bottom-[-20%] left-[-20%] w-[45%] h-[45%] bg-purple-600/6 blur-[120px] rounded-full pointer-events-none" />

      {/* ── HERO HEADER ──────────────────────────────── */}
      <div className="relative border-b border-white/5 bg-gradient-to-b from-indigo-500/5 to-transparent py-16 mb-10">
        <div className="max-w-5xl mx-auto px-6">
          {/* Breadcrumb */}
          <nav className="flex items-center gap-2 text-xs font-black text-neutral-600 uppercase tracking-widest mb-6">
            <Link href="/" className="hover:text-white transition">QuickEx</Link>
            <span>/</span>
            <span className="text-neutral-400">Marketplace</span>
          </nav>

          <div className="flex flex-col md:flex-row md:items-end justify-between gap-6">
            <div>
              <div className="inline-flex items-center gap-2 px-3 py-1 bg-indigo-500/10 border border-indigo-500/20 rounded-full mb-4">
                <span className="w-2 h-2 rounded-full bg-indigo-400 animate-pulse" />
                <span className="text-xs font-black text-indigo-300 tracking-widest uppercase">
                  Live Auctions
                </span>
              </div>
              <h1 className="text-5xl md:text-6xl font-black tracking-tight bg-gradient-to-br from-white via-neutral-200 to-neutral-500 bg-clip-text text-transparent leading-none mb-4">
                Username<br />Marketplace
              </h1>
              <p className="text-neutral-400 max-w-lg leading-relaxed">
                Bid on rare, short, and premium Stellar usernames. Own your identity on-chain — permanent, self-custodied, and transferable.
              </p>
            </div>

            <Link
              href="/dashboard?tab=listings"
              className="shrink-0 px-6 py-4 bg-white/5 hover:bg-white/10 border border-white/10 rounded-2xl font-bold text-sm transition-all hover:border-white/20 whitespace-nowrap"
            >
              My Listings & Bids →
            </Link>
          </div>
        </div>
      </div>

      {/* ── MAIN CONTENT ─────────────────────────────── */}
      <div className="max-w-5xl mx-auto px-6 pb-24">
        {!loading && <StatsBar listings={listings} />}

        {/* ── CONTROLS ─────────────────────────────── */}
        <div className="flex flex-col gap-4 mb-8">
          {/* Search */}
          <div className="relative">
            <span className="absolute left-4 top-1/2 -translate-y-1/2 text-neutral-500 text-lg pointer-events-none">
              ⌕
            </span>
            <input
              id="marketplace-search"
              type="text"
              placeholder="Search usernames…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full bg-white/5 border border-white/8 focus:border-indigo-500/50 rounded-2xl pl-11 pr-5 py-4 text-white placeholder-neutral-600 font-medium outline-none transition-all text-sm"
            />
            {search && (
              <button
                onClick={() => setSearch("")}
                className="absolute right-4 top-1/2 -translate-y-1/2 text-neutral-500 hover:text-white transition text-sm"
              >
                ✕
              </button>
            )}
          </div>

          {/* Filters row */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            {/* Category pills */}
            <div className="flex items-center gap-2 flex-wrap">
              {CATEGORIES.map((cat) => (
                <button
                  key={cat.key}
                  id={`filter-${cat.key}`}
                  onClick={() => setActiveCategory(cat.key)}
                  className={`flex items-center gap-1.5 px-3.5 py-2 rounded-xl font-bold text-xs transition-all ${
                    activeCategory === cat.key
                      ? "bg-indigo-500 text-white shadow-[0_4px_20px_-8px_rgba(99,102,241,0.8)]"
                      : "bg-white/5 border border-white/5 text-neutral-400 hover:text-white hover:bg-white/10"
                  }`}
                >
                  <span>{cat.icon}</span>
                  {cat.label}
                </button>
              ))}
            </div>

            {/* Sort dropdown */}
            <select
              id="marketplace-sort"
              value={sortKey}
              onChange={(e) => setSortKey(e.target.value)}
              className="bg-white/5 border border-white/8 text-sm font-bold text-neutral-400 rounded-xl px-4 py-2 outline-none focus:border-indigo-500/40 transition"
            >
              {SORT_OPTIONS.map((o) => (
                <option key={o.key} value={o.key}>
                  {o.label}
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* ── RESULTS COUNT ─────────────────────────── */}
        {!loading && (
          <p className="text-xs text-neutral-600 font-bold uppercase tracking-widest mb-6">
            {filtered.length} listing{filtered.length !== 1 ? "s" : ""} found
            {search && ` for "${search}"`}
          </p>
        )}

        {/* ── GRID ─────────────────────────────────── */}
        {loading ? (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
            {Array.from({ length: 6 }).map((_, i) => (
              <div
                key={i}
                className="h-72 rounded-3xl bg-white/[0.03] border border-white/5 animate-pulse"
              />
            ))}
          </div>
        ) : filtered.length === 0 ? (
          <div className="py-32 text-center">
            <p className="text-5xl mb-6">🔍</p>
            <h3 className="text-xl font-black mb-2">No results</h3>
            <p className="text-neutral-500 text-sm">
              Try a different search term or category.
            </p>
            <button
              onClick={() => { setSearch(""); setActiveCategory("all"); }}
              className="mt-6 px-6 py-3 bg-white/5 border border-white/10 rounded-xl font-bold text-sm hover:bg-white/10 transition"
            >
              Clear Filters
            </button>
          </div>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
            {filtered.map((listing) => (
              <UsernameCard
                key={listing.id}
                listing={listing}
                onBid={setActiveListing}
              />
            ))}
          </div>
        )}
      </div>

      {/* ── BID MODAL ─────────────────────────────── */}
      <BidModal
        listing={activeListing}
        onClose={() => setActiveListing(null)}
        onBidSuccess={(username, amount) => {
          handleBidSuccess(username, amount);
          setTimeout(() => setActiveListing(null), 2500);
        }}
      />
    </div>
  );
}
