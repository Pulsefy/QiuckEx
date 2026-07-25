"use client";

import { useState } from "react";
import Link from "next/link";
import { SearchBar } from "@/components/SearchBar";
import { useUnifiedSearch } from "@/hooks/useUnifiedSearch";

export default function DiscoveryPage() {
  const [searchQuery, setSearchQuery] = useState("");
  const [scope, setScope] = useState<"all" | "profiles" | "listings">("all");

  const {
    profiles,
    listings,
    didYouMean,
    totalProfiles,
    totalListings,
    isLoading,
  } = useUnifiedSearch(searchQuery, scope);

  const hasSearch = searchQuery.trim().length > 0;

  return (
    <div className="max-w-6xl mx-auto space-y-12 py-8 px-4 selection:bg-indigo-500/30">
      {/* Discovery Hero Section */}
      <header className="space-y-6 text-center max-w-3xl mx-auto">
        <div className="w-16 h-16 bg-indigo-500/10 rounded-3xl flex items-center justify-center mx-auto border border-indigo-500/20 shadow-xl shadow-indigo-500/10">
          <span className="text-3xl">🔭</span>
        </div>
        <h1 className="text-4xl md:text-6xl font-black tracking-tighter">
          Unified Search & <span className="text-transparent bg-clip-text bg-gradient-to-r from-indigo-400 via-cyan-400 to-emerald-400">Discovery</span>
        </h1>
        <p className="text-base md:text-lg text-subtle leading-relaxed">
          Search across global QuickEx public profiles and active marketplace domain listings using one unified backend contract.
        </p>

        {/* Prominent Search Bar */}
        <div className="pt-4 max-w-2xl mx-auto">
          <SearchBar
            placeholder="Search usernames, creators, or domain listings..."
            className="text-left"
          />
        </div>
      </header>

      {/* Scope Filter Tabs */}
      <div className="flex flex-wrap items-center justify-between border-b border-border/80 pb-4 gap-4">
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setScope("all")}
            className={`px-4 py-2 text-sm font-semibold rounded-xl transition-all ${
              scope === "all"
                ? "bg-indigo-500 text-white shadow-lg shadow-indigo-500/25"
                : "bg-card border border-border text-subtle hover:text-foreground"
            }`}
          >
            All Surfaces
          </button>
          <button
            type="button"
            onClick={() => setScope("profiles")}
            className={`px-4 py-2 text-sm font-semibold rounded-xl transition-all ${
              scope === "profiles"
                ? "bg-indigo-500 text-white shadow-lg shadow-indigo-500/25"
                : "bg-card border border-border text-subtle hover:text-foreground"
            }`}
          >
            👤 Profiles
          </button>
          <button
            type="button"
            onClick={() => setScope("listings")}
            className={`px-4 py-2 text-sm font-semibold rounded-xl transition-all ${
              scope === "listings"
                ? "bg-indigo-500 text-white shadow-lg shadow-indigo-500/25"
                : "bg-card border border-border text-subtle hover:text-foreground"
            }`}
          >
            🏷️ Marketplace Listings
          </button>
        </div>
        <div className="text-xs text-subtle font-medium">
          Powered by QuickEx Horizon API & Supabase
        </div>
      </div>

      {/* Search Output Section */}
      {hasSearch ? (
        <section className="space-y-8">
          {/* Typo Suggestion Banner */}
          {didYouMean && (
            <div className="p-4 rounded-2xl bg-amber-500/10 border border-amber-500/30 text-amber-300 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <span className="text-xl">💡</span>
                <p className="text-sm">
                  No exact matches for &quot;<strong>{searchQuery}</strong>&quot;. Did you mean{" "}
                  <button
                    type="button"
                    onClick={() => setSearchQuery(didYouMean)}
                    className="font-bold underline hover:text-amber-200"
                  >
                    &quot;{didYouMean}&quot;
                  </button>
                  ?
                </p>
              </div>
              <button
                type="button"
                onClick={() => setSearchQuery(didYouMean)}
                className="px-4 py-1.5 bg-amber-500/20 text-amber-200 rounded-xl font-bold text-xs hover:bg-amber-500/30 transition"
              >
                Search &quot;{didYouMean}&quot;
              </button>
            </div>
          )}

          {isLoading ? (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {[...Array(4)].map((_, i) => (
                <div key={i} className="p-6 rounded-3xl bg-card/40 border border-border animate-pulse h-36"></div>
              ))}
            </div>
          ) : profiles.length > 0 || listings.length > 0 ? (
            <div className="space-y-10">
              {/* Profiles Result Section */}
              {(scope === "all" || scope === "profiles") && profiles.length > 0 && (
                <div className="space-y-4">
                  <h2 className="text-xl font-bold flex items-center gap-2 text-foreground">
                    <span>👤</span> Profiles ({totalProfiles})
                  </h2>
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                    {profiles.map((user) => (
                      <Link key={user.id} href={`/profile/${user.username}`} className="block group">
                        <div className="p-6 rounded-3xl bg-card border border-border hover:border-indigo-500/40 hover:bg-card/80 transition-all flex flex-col justify-between shadow-xl shadow-black/20 group-hover:shadow-indigo-500/10">
                          <div className="flex items-start justify-between mb-4">
                            <div
                              className={`w-12 h-12 rounded-2xl flex items-center justify-center font-bold text-lg text-white shadow-inner ${
                                user.avatarColor || "bg-indigo-500"
                              }`}
                            >
                              {user.name ? user.name.charAt(0) : user.username.charAt(0).toUpperCase()}
                            </div>
                            <span className="text-xs font-medium text-subtle bg-surface px-2.5 py-1 rounded-full border border-border">
                              {user.followers ? user.followers.toLocaleString() : 120} followers
                            </span>
                          </div>
                          <div>
                            <h3 className="text-base font-bold text-foreground group-hover:text-indigo-400 transition-colors">
                              {user.name || user.username}
                            </h3>
                            <p className="text-xs text-brand/90 font-medium mb-2">@{user.username}</p>
                            {user.bio && <p className="text-xs text-subtle line-clamp-2">{user.bio}</p>}
                          </div>
                          <div className="mt-4 pt-3 border-t border-border/60 flex items-center justify-between text-xs font-semibold text-indigo-400">
                            <span>View Profile</span>
                            <span>→</span>
                          </div>
                        </div>
                      </Link>
                    ))}
                  </div>
                </div>
              )}

              {/* Listings Result Section */}
              {(scope === "all" || scope === "listings") && listings.length > 0 && (
                <div className="space-y-4">
                  <h2 className="text-xl font-bold flex items-center gap-2 text-foreground">
                    <span>🏷️</span> Marketplace Listings ({totalListings})
                  </h2>
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                    {listings.map((item) => (
                      <Link key={item.id} href={`/marketplace?listing=${item.id}`} className="block group">
                        <div className="p-6 rounded-3xl bg-card border border-border hover:border-cyan-500/40 hover:bg-card/80 transition-all flex flex-col justify-between shadow-xl shadow-black/20 group-hover:shadow-cyan-500/10">
                          <div className="flex items-start justify-between mb-4">
                            <div className="w-12 h-12 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 text-xl font-bold">
                              🏷️
                            </div>
                            {item.category && (
                              <span className="text-xs font-bold text-cyan-300 bg-cyan-500/10 border border-cyan-500/30 px-2.5 py-1 rounded-full uppercase">
                                {item.category}
                              </span>
                            )}
                          </div>
                          <div>
                            <h3 className="text-lg font-black text-foreground group-hover:text-cyan-300 transition-colors">
                              quickex.to/{item.username}
                            </h3>
                            <div className="mt-2 space-y-1">
                              <p className="text-xs text-subtle">
                                Asking Price: <span className="font-bold text-emerald-400">{item.askingPrice} XLM</span>
                              </p>
                              {item.currentBid && (
                                <p className="text-xs text-subtle">
                                  Current Top Bid: <span className="font-semibold text-cyan-300">{item.currentBid} XLM</span>
                                </p>
                              )}
                            </div>
                          </div>
                          <div className="mt-4 pt-3 border-t border-border/60 flex items-center justify-between text-xs font-semibold text-cyan-400">
                            <span>Place Bid / Buy Now</span>
                            <span>→</span>
                          </div>
                        </div>
                      </Link>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ) : (
            /* No Results State */
            <div className="p-12 rounded-3xl bg-card border border-border text-center space-y-4 max-w-xl mx-auto shadow-xl">
              <div className="w-16 h-16 rounded-3xl bg-surface border border-border flex items-center justify-center text-3xl mx-auto">
                🔍
              </div>
              <h3 className="text-xl font-bold text-foreground">No matches found for &quot;{searchQuery}&quot;</h3>
              <p className="text-sm text-subtle">
                We couldn&apos;t find any usernames or marketplace listings matching your search scope. Try broadening your query or clearing filters.
              </p>
              <button
                type="button"
                onClick={() => setSearchQuery("")}
                className="px-6 py-2.5 bg-surface hover:bg-surface-strong text-foreground font-semibold rounded-xl text-xs transition border border-border"
              >
                Clear Search
              </button>
            </div>
          )}
        </section>
      ) : (
        /* Discovery Default Grid */
        <section className="space-y-8">
          <div className="flex items-center justify-between">
            <h2 className="text-2xl font-bold flex items-center gap-3">
              <span className="text-orange-500 text-3xl">🔥</span> Featured Community Members
            </h2>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            {profiles.slice(0, 4).map((user) => (
              <Link key={user.id} href={`/profile/${user.username}`} className="block group">
                <div className="p-6 rounded-3xl bg-card border border-border hover:border-indigo-500/30 hover:bg-card/80 transition-all h-full flex flex-col shadow-lg shadow-black/20">
                  <div className="flex items-start justify-between mb-5">
                    <div className={`w-14 h-14 rounded-2xl flex items-center justify-center font-bold text-2xl shadow-inner ${user.avatarColor || "bg-indigo-500"}`}>
                      {user.name ? user.name.charAt(0) : user.username.charAt(0).toUpperCase()}
                    </div>
                  </div>
                  <h3 className="text-lg font-bold text-foreground group-hover:text-indigo-400 transition-colors">{user.name || user.username}</h3>
                  <p className="text-sm text-brand/80 mb-4 tracking-tight">@{user.username}</p>
                  <p className="text-sm text-subtle flex-1 leading-relaxed">{user.bio}</p>
                </div>
              </Link>
            ))}
          </div>
        </section>
      )}
    </div>
  );
}
