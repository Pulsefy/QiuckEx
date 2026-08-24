"use client";

import { useState, useEffect, useRef, useCallback } from "react";
import { useRouter } from "next/navigation";
import {
  searchDiscovery,
  MIN_SEARCH_LENGTH,
  type SearchDiscoveryResult,
} from "@/lib/discoveryApi";

type FlatResult = { href: string; result: SearchDiscoveryResult };

const LISTING_STATUS_LABELS: Record<string, string> = {
  auction: "Auction",
  buyNow: "Buy now",
  listed: "Listed",
  sold: "Sold",
};

function flattenResults(
  profiles: SearchDiscoveryResult[],
  listings: SearchDiscoveryResult[]
): FlatResult[] {
  return [
    ...profiles.map((result) => ({
      href: `/profile/${encodeURIComponent(result.username)}`,
      result,
    })),
    ...listings.map((result) => ({
      href: `/marketplace/${encodeURIComponent(result.id)}`,
      result,
    })),
  ];
}

export function SearchBar() {
  const router = useRouter();
  const [query, setQuery] = useState("");
  const [isOpen, setIsOpen] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [profiles, setProfiles] = useState<SearchDiscoveryResult[]>([]);
  const [listings, setListings] = useState<SearchDiscoveryResult[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [retryCount, setRetryCount] = useState(0);
  const [activeIndex, setActiveIndex] = useState(-1);
  const dropdownRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    // Click outside to close
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  useEffect(() => {
    const trimmed = query.trim();
    if (trimmed.length < MIN_SEARCH_LENGTH) {
      setProfiles([]);
      setListings([]);
      setIsLoading(false);
      setError(null);
      setActiveIndex(-1);
      return;
    }

    setIsLoading(true);
    setIsOpen(true);
    setError(null);
    setActiveIndex(-1);

    const controller = new AbortController();
    const timer = setTimeout(() => {
      searchDiscovery(trimmed, { limit: 10, signal: controller.signal })
        .then((grouped) => {
          setProfiles(grouped.profiles);
          setListings(grouped.listings);
          setIsLoading(false);
        })
        .catch((err: unknown) => {
          if (controller.signal.aborted) return;
          setProfiles([]);
          setListings([]);
          setError(
            err instanceof Error ? err.message : "Something went wrong while searching."
          );
          setIsLoading(false);
        });
    }, 300);

    return () => {
      clearTimeout(timer);
      controller.abort();
    };
  }, [query, retryCount]);

  const flatResults =
    isLoading || error ? [] : flattenResults(profiles, listings);

  const selectResult = useCallback(
    (index: number) => {
      const target = flatResults[index];
      if (!target) return;
      setIsOpen(false);
      setQuery("");
      router.push(target.href);
    },
    [flatResults, router]
  );

  const handleKeyDown = (event: React.KeyboardEvent<HTMLInputElement>) => {
    if (event.key === "Escape") {
      setIsOpen(false);
      setActiveIndex(-1);
      return;
    }
    if (!flatResults.length) return;
    if (event.key === "ArrowDown") {
      event.preventDefault();
      setActiveIndex((prev) => (prev + 1) % flatResults.length);
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      setActiveIndex(
        (prev) => (prev - 1 + flatResults.length) % flatResults.length
      );
    } else if (event.key === "Enter" && activeIndex >= 0) {
      event.preventDefault();
      selectResult(activeIndex);
    }
  };

  const renderProfileRow = (
    user: SearchDiscoveryResult,
    index: number
  ) => (
    <button
      key={`profile-${user.id}`}
      type="button"
      role="option"
      aria-selected={activeIndex === index}
      className="flex w-full items-center gap-4 px-4 py-2 hover:bg-surface transition group text-left data-[active=true]:bg-surface"
      data-active={activeIndex === index}
      onMouseEnter={() => setActiveIndex(index)}
      onClick={() => selectResult(index)}
    >
      <div className="w-10 h-10 rounded-full flex items-center justify-center font-bold text-sm shadow-inner bg-indigo-500/20 text-indigo-300">
        {user.username.charAt(0).toUpperCase()}
      </div>
      <div className="flex-1 flex flex-col items-start overflow-hidden">
        <span className="text-sm font-semibold text-foreground group-hover:text-indigo-400 transition-colors truncate">
          @{user.username}
        </span>
        <span className="text-xs text-subtle truncate">
          Profile
          {typeof user.similarityScore === "number"
            ? ` · ${Math.round(user.similarityScore)}% match`
            : ""}
        </span>
      </div>
    </button>
  );

  const renderListingRow = (
    listing: SearchDiscoveryResult,
    index: number
  ) => (
    <button
      key={`listing-${listing.id}`}
      type="button"
      role="option"
      aria-selected={activeIndex === index}
      className="flex w-full items-center gap-4 px-4 py-2 hover:bg-surface transition group text-left data-[active=true]:bg-surface"
      data-active={activeIndex === index}
      onMouseEnter={() => setActiveIndex(index)}
      onClick={() => selectResult(index)}
    >
      <div className="w-10 h-10 rounded-xl flex items-center justify-center shadow-inner bg-emerald-500/15 text-emerald-300">
        <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 7h.01M7 3h5c.512 0 1.024.195 1.414.586l7 7a2 2 0 010 2.828l-7 7a2 2 0 01-2.828 0l-7-7A1.994 1.994 0 013 12V7a4 4 0 014-4z" />
        </svg>
      </div>
      <div className="flex-1 flex flex-col items-start overflow-hidden">
        <span className="text-sm font-semibold text-foreground group-hover:text-indigo-400 transition-colors truncate">
          @{listing.username}
        </span>
        <span className="text-xs text-subtle truncate">
          Marketplace listing
          {listing.status ? ` · ${LISTING_STATUS_LABELS[listing.status] ?? listing.status}` : ""}
        </span>
      </div>
      {typeof listing.askingPrice === "number" && (
        <span className="text-xs font-semibold text-brand whitespace-nowrap">
          ${listing.askingPrice.toLocaleString()} USDC
        </span>
      )}
    </button>
  );

  const hasResults = flatResults.length > 0;

  return (
    <div className="relative w-full max-w-md" ref={dropdownRef}>
      <div role="combobox" aria-expanded={isOpen} aria-haspopup="listbox" aria-owns="unified-search-results">
        <div className="relative flex items-center">
          <svg className="absolute left-3 w-4 h-4 text-subtle pointer-events-none" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
          <input
            type="text"
            role="searchbox"
            aria-label="Search profiles and marketplace listings"
            aria-autocomplete="list"
            aria-controls="unified-search-results"
            placeholder="Search profiles and listings..."
            className="w-full bg-card/50 border border-border-strong rounded-full pl-10 pr-10 py-2 text-sm text-foreground placeholder-neutral-500 focus:outline-none focus:border-indigo-500/50 focus:ring-1 focus:ring-indigo-500/50 transition-all font-medium"
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              if (!isOpen) setIsOpen(true);
            }}
            onKeyDown={handleKeyDown}
            onFocus={() => {
              if (query.trim().length >= MIN_SEARCH_LENGTH) setIsOpen(true);
            }}
          />
          {query && (
            <button
              className="absolute right-3 text-subtle hover:text-foreground transition"
              onClick={() => {
                setQuery("");
                setIsOpen(false);
              }}
              title="Clear"
              aria-label="Clear search"
            >
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          )}
        </div>

        {isOpen && query.trim() && (
          <div
            id="unified-search-results"
            role="listbox"
            aria-label="Search results"
            className="absolute top-full lg:left-0 -left-10 lg:w-full w-[120%] mt-2 bg-card border border-border-strong rounded-2xl shadow-2xl overflow-hidden z-50 animate-in fade-in slide-in-from-top-2 duration-200"
          >
            {query.trim().length < MIN_SEARCH_LENGTH ? (
              <div className="p-8 text-center text-sm text-subtle">
                Type at least {MIN_SEARCH_LENGTH} characters to search.
              </div>
            ) : isLoading ? (
              <div className="p-2 space-y-1" aria-live="polite" aria-busy="true">
                {[...Array(3)].map((_, i) => (
                  <div key={i} className="flex items-center gap-3 p-2 animate-pulse rounded-xl bg-card/[0.02]">
                    <div className="w-10 h-10 rounded-full bg-surface-strong"></div>
                    <div className="flex-1 space-y-2">
                      <div className="h-3 bg-surface-strong rounded w-1/3"></div>
                      <div className="h-2 bg-surface-strong rounded w-1/2"></div>
                    </div>
                  </div>
                ))}
              </div>
            ) : error ? (
              <div className="p-8 text-center text-sm text-subtle flex flex-col items-center gap-3">
                <p>{error}</p>
                <button
                  type="button"
                  className="px-4 py-2 rounded-full border border-border-strong text-foreground font-medium hover:bg-surface transition"
                  onClick={() => setRetryCount((c) => c + 1)}
                >
                  Try again
                </button>
              </div>
            ) : hasResults ? (
              <div className="flex flex-col py-2">
                {profiles.length > 0 && (
                  <>
                    <div className="px-4 py-2 text-xs font-semibold text-subtle uppercase tracking-wider mb-1">
                      Profiles
                    </div>
                    {profiles.map((user, i) => renderProfileRow(user, i))}
                  </>
                )}
                {listings.length > 0 && (
                  <>
                    <div className="px-4 py-2 text-xs font-semibold text-subtle uppercase tracking-wider mb-1 mt-1 border-t border-border pt-3">
                      Marketplace Listings
                    </div>
                    {listings.map((listing, i) =>
                      renderListingRow(listing, profiles.length + i)
                    )}
                  </>
                )}
              </div>
            ) : (
              <div className="p-8 text-center text-sm text-subtle flex flex-col items-center gap-3">
                <div className="w-12 h-12 rounded-full bg-surface flex items-center justify-center text-2xl">
                  🔍
                </div>
                <p>No results found for &quot;{query}&quot;</p>
                <p className="text-xs text-muted">
                  Fuzzy matching is on — check the spelling or try a shorter query.
                </p>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
