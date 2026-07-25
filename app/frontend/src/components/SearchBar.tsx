"use client";

import { useState, useEffect, useRef } from "react";
import Link from "next/link";
import { useUnifiedSearch } from "@/hooks/useUnifiedSearch";

interface SearchBarProps {
  placeholder?: string;
  className?: string;
  onSelectResult?: () => void;
}

export function SearchBar({ placeholder = "Search profiles & marketplace listings...", className = "", onSelectResult }: SearchBarProps) {
  const [query, setQuery] = useState("");
  const [isOpen, setIsOpen] = useState(false);
  const [activeScope, setActiveScope] = useState<"all" | "profiles" | "listings">("all");
  const dropdownRef = useRef<HTMLDivElement>(null);

  const { profiles, listings, didYouMean, totalProfiles, totalListings, isLoading } = useUnifiedSearch(query, activeScope);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  const hasResults = profiles.length > 0 || listings.length > 0;

  return (
    <div className={`relative w-full ${className}`} ref={dropdownRef}>
      {/* Search Input Bar */}
      <div className="relative flex items-center">
        <svg
          className="absolute left-3.5 w-4 h-4 text-subtle pointer-events-none"
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"
          />
        </svg>
        <input
          type="text"
          placeholder={placeholder}
          className="w-full bg-card/60 border border-border-strong rounded-full pl-10 pr-10 py-2.5 text-sm text-foreground placeholder-neutral-400 focus:outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/30 transition-all font-medium backdrop-blur-md shadow-lg shadow-black/10"
          value={query}
          onChange={(e) => {
            setQuery(e.target.value);
            if (!isOpen) setIsOpen(true);
          }}
          onFocus={() => {
            if (query.trim()) setIsOpen(true);
          }}
        />
        {query && (
          <button
            type="button"
            className="absolute right-3.5 p-1 rounded-full text-subtle hover:text-foreground hover:bg-surface transition"
            onClick={() => setQuery("")}
            title="Clear search"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        )}
      </div>

      {/* Unified Search Dropdown Popup */}
      {isOpen && query.trim() && (
        <div className="absolute top-full left-0 w-full mt-2 bg-card/95 border border-border-strong rounded-2xl shadow-2xl overflow-hidden z-50 animate-in fade-in slide-in-from-top-2 duration-200 backdrop-blur-xl max-h-[480px] flex flex-col">
          {/* Filter Scope Tabs */}
          <div className="flex items-center gap-1 p-2 border-b border-border/60 bg-surface/30">
            <button
              type="button"
              onClick={() => setActiveScope("all")}
              className={`px-3 py-1 text-xs font-semibold rounded-lg transition-colors ${
                activeScope === "all"
                  ? "bg-indigo-500 text-white shadow-sm"
                  : "text-subtle hover:text-foreground hover:bg-surface"
              }`}
            >
              All ({totalProfiles + totalListings})
            </button>
            <button
              type="button"
              onClick={() => setActiveScope("profiles")}
              className={`px-3 py-1 text-xs font-semibold rounded-lg transition-colors ${
                activeScope === "profiles"
                  ? "bg-indigo-500 text-white shadow-sm"
                  : "text-subtle hover:text-foreground hover:bg-surface"
              }`}
            >
              👤 Profiles ({totalProfiles})
            </button>
            <button
              type="button"
              onClick={() => setActiveScope("listings")}
              className={`px-3 py-1 text-xs font-semibold rounded-lg transition-colors ${
                activeScope === "listings"
                  ? "bg-indigo-500 text-white shadow-sm"
                  : "text-subtle hover:text-foreground hover:bg-surface"
              }`}
            >
              🏷️ Listings ({totalListings})
            </button>
          </div>

          {/* Typo Tolerance Suggestion Banner */}
          {didYouMean && (
            <div className="px-4 py-2 bg-amber-500/10 border-b border-amber-500/20 text-xs text-amber-300 flex items-center justify-between">
              <span>
                Did you mean{" "}
                <button
                  type="button"
                  onClick={() => setQuery(didYouMean)}
                  className="font-bold underline hover:text-amber-200"
                >
                  &quot;{didYouMean}&quot;
                </button>
                ?
              </span>
              <button
                type="button"
                onClick={() => setQuery(didYouMean)}
                className="px-2 py-0.5 bg-amber-500/20 rounded font-semibold text-[10px] hover:bg-amber-500/30"
              >
                Apply
              </button>
            </div>
          )}

          {/* Results Container */}
          <div className="overflow-y-auto divide-y divide-border/40 flex-1">
            {isLoading ? (
              <div className="p-4 space-y-3">
                {[...Array(3)].map((_, i) => (
                  <div key={i} className="flex items-center gap-3 animate-pulse">
                    <div className="w-9 h-9 rounded-full bg-surface-strong"></div>
                    <div className="flex-1 space-y-1.5">
                      <div className="h-3 bg-surface-strong rounded w-1/3"></div>
                      <div className="h-2.5 bg-surface-strong rounded w-1/2"></div>
                    </div>
                  </div>
                ))}
              </div>
            ) : hasResults ? (
              <>
                {/* Profiles Group */}
                {profiles.length > 0 && (
                  <div className="py-2">
                    <div className="px-4 py-1.5 text-[11px] font-bold text-indigo-400 uppercase tracking-wider flex items-center justify-between">
                      <span>👤 Profiles</span>
                      <span className="text-[10px] text-subtle">{profiles.length}</span>
                    </div>
                    {profiles.map((user) => (
                      <Link
                        key={user.id}
                        href={`/profile/${user.username}`}
                        className="flex items-center gap-3 px-4 py-2.5 hover:bg-indigo-500/10 transition group"
                        onClick={() => {
                          setIsOpen(false);
                          if (onSelectResult) onSelectResult();
                        }}
                      >
                        <div
                          className={`w-9 h-9 rounded-full flex items-center justify-center font-bold text-xs text-white shadow-inner ${
                            user.avatarColor || "bg-indigo-500"
                          }`}
                        >
                          {user.name ? user.name.charAt(0) : user.username.charAt(0).toUpperCase()}
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2">
                            <span className="text-sm font-semibold text-foreground group-hover:text-indigo-300 transition-colors truncate">
                              {user.name || user.username}
                            </span>
                            <span className="text-xs text-brand/90 truncate">@{user.username}</span>
                          </div>
                          {user.bio && <p className="text-xs text-subtle truncate">{user.bio}</p>}
                        </div>
                        <span className="text-xs text-subtle group-hover:text-indigo-400 transition-colors">
                          →
                        </span>
                      </Link>
                    ))}
                  </div>
                )}

                {/* Listings Group */}
                {listings.length > 0 && (
                  <div className="py-2">
                    <div className="px-4 py-1.5 text-[11px] font-bold text-cyan-400 uppercase tracking-wider flex items-center justify-between">
                      <span>🏷️ Marketplace Listings</span>
                      <span className="text-[10px] text-subtle">{listings.length}</span>
                    </div>
                    {listings.map((item) => (
                      <Link
                        key={item.id}
                        href={`/marketplace?listing=${item.id}`}
                        className="flex items-center gap-3 px-4 py-2.5 hover:bg-cyan-500/10 transition group"
                        onClick={() => {
                          setIsOpen(false);
                          if (onSelectResult) onSelectResult();
                        }}
                      >
                        <div className="w-9 h-9 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 font-bold text-sm">
                          🏷️
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2">
                            <span className="text-sm font-bold text-foreground group-hover:text-cyan-300 transition-colors truncate">
                              {item.username}.to
                            </span>
                            {item.category && (
                              <span className="px-1.5 py-0.5 text-[10px] font-semibold bg-surface border border-border rounded text-subtle uppercase">
                                {item.category}
                              </span>
                            )}
                          </div>
                          <p className="text-xs text-subtle truncate">
                            Asking: <span className="font-semibold text-emerald-400">{item.askingPrice} XLM</span>
                            {item.currentBid ? ` · Top Bid: ${item.currentBid} XLM` : ""}
                          </p>
                        </div>
                        <span className="text-xs font-semibold px-2 py-1 bg-cyan-500/20 text-cyan-300 rounded-lg group-hover:bg-cyan-500/30 transition">
                          View
                        </span>
                      </Link>
                    ))}
                  </div>
                )}
              </>
            ) : (
              /* Polished Empty State */
              <div className="p-8 text-center text-subtle flex flex-col items-center gap-3">
                <div className="w-12 h-12 rounded-2xl bg-surface/50 border border-border flex items-center justify-center text-2xl">
                  🔍
                </div>
                <div className="space-y-1">
                  <p className="text-sm font-semibold text-foreground">No results found for &quot;{query}&quot;</p>
                  <p className="text-xs text-subtle">
                    Try checking for typos or searching for a different username or domain asset.
                  </p>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
