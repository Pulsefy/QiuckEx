"use client";

import { useState, useEffect, useRef, useId, useCallback } from "react";
import Link from "next/link";
import { useProfileSearch, PublicProfile } from "@/hooks/useDiscoveryProfiles";

export function SearchBar() {
  const [query, setQuery] = useState("");
  const [isOpen, setIsOpen] = useState(false);
  const [activeIndex, setActiveIndex] = useState(-1);
  const { isLoading, results, error } = useProfileSearch(query);

  const containerRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const optionRefs = useRef<Array<HTMLAnchorElement | null>>([]);

  const baseId = useId();
  const listboxId = `${baseId}-listbox`;
  const getOptionId = (index: number) => `${baseId}-option-${index}`;

  const hasResults = results.length > 0;
  const isExpanded = isOpen && Boolean(query.trim());

  useEffect(() => {
    // Click outside to close
    const handleClickOutside = (event: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  // Reset the highlight whenever the result set or query changes.
  useEffect(() => {
    setActiveIndex(-1);
  }, [query, results]);

  const closeDropdown = useCallback(() => {
    setIsOpen(false);
    setActiveIndex(-1);
  }, []);

  const handleKeyDown = (event: React.KeyboardEvent<HTMLInputElement>) => {
    if (event.key === "Escape") {
      if (isOpen) {
        event.preventDefault();
        closeDropdown();
      }
      return;
    }

    if (!isExpanded || !hasResults) return;

    if (event.key === "ArrowDown") {
      event.preventDefault();
      setActiveIndex((current) => {
        const next = current + 1 >= results.length ? 0 : current + 1;
        optionRefs.current[next]?.scrollIntoView?.({ block: "nearest" });
        return next;
      });
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      setActiveIndex((current) => {
        const next = current - 1 < 0 ? results.length - 1 : current - 1;
        optionRefs.current[next]?.scrollIntoView?.({ block: "nearest" });
        return next;
      });
    } else if (event.key === "Enter") {
      if (activeIndex >= 0 && activeIndex < results.length) {
        event.preventDefault();
        const selected = results[activeIndex];
        closeDropdown();
        inputRef.current?.blur();
        window.location.assign(`/profile/${selected.username}`);
      }
    }
  };

  return (
    <div className="relative w-full" ref={containerRef}>
      <div className="relative flex items-center">
        <svg
          className="absolute left-3 w-4 h-4 text-subtle"
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
          aria-hidden="true"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
        </svg>
        <input
          ref={inputRef}
          type="text"
          role="combobox"
          aria-label="Search global profiles"
          aria-autocomplete="list"
          aria-expanded={isExpanded}
          aria-controls={listboxId}
          aria-activedescendant={isExpanded && activeIndex >= 0 ? getOptionId(activeIndex) : undefined}
          placeholder="Search global profiles..."
          className="w-full bg-card/50 border border-border-strong rounded-full pl-10 pr-10 py-2 text-sm text-foreground placeholder-neutral-500 focus:outline-none focus:border-indigo-500/50 focus:ring-1 focus:ring-indigo-500/50 transition-all font-medium"
          value={query}
          onChange={(e) => {
            setQuery(e.target.value);
            setIsOpen(true);
          }}
          onFocus={() => {
            if (query.trim()) setIsOpen(true);
          }}
          onKeyDown={handleKeyDown}
        />
        {query && (
          <button
            type="button"
            className="absolute right-3 text-subtle hover:text-foreground transition"
            onClick={() => {
              setQuery("");
              setActiveIndex(-1);
              inputRef.current?.focus();
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

      <div
        role="status"
        aria-live="polite"
        className="sr-only"
      >
        {isExpanded
          ? isLoading
            ? "Searching profiles"
            : `${results.length} result${results.length === 1 ? "" : "s"} available`
          : ""}
      </div>

      {isExpanded && (
        <div
          id={listboxId}
          role="listbox"
          aria-label="Profile search results"
          className="absolute top-full lg:left-0 -left-10 lg:w-full w-[120%] mt-2 bg-card border border-border-strong rounded-2xl shadow-2xl overflow-hidden z-50 animate-in fade-in slide-in-from-top-2 duration-200"
        >
          {isLoading ? (
            <div className="p-2 space-y-1">
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
            <div className="p-8 text-center text-sm text-warning">{error}</div>
          ) : hasResults ? (
            <div className="flex flex-col py-2">
              <div className="px-4 py-2 text-xs font-semibold text-subtle uppercase tracking-wider mb-1">
                Profiles
              </div>
              {results.map((user: PublicProfile, index: number) => {
                const isActive = index === activeIndex;
                return (
                  <Link
                    key={user.id}
                    id={getOptionId(index)}
                    ref={(node) => {
                      optionRefs.current[index] = node;
                    }}
                    role="option"
                    aria-selected={isActive}
                    href={`/profile/${user.username}`}
                    className={`flex items-center gap-4 px-4 py-2 transition group ${
                      isActive ? "bg-surface" : "hover:bg-surface"
                    }`}
                    onClick={closeDropdown}
                    onMouseEnter={() => setActiveIndex(index)}
                  >
                    <div className="w-10 h-10 rounded-full bg-indigo-500/15 flex items-center justify-center font-bold text-sm shadow-inner text-indigo-300">
                      {user.username.charAt(0).toUpperCase()}
                    </div>
                    <div className="flex-1 flex flex-col items-start overflow-hidden">
                      <span className="text-sm font-semibold text-foreground group-hover:text-indigo-400 transition-colors truncate">@{user.username}</span>
                      <span className="text-xs text-subtle truncate">@{user.username}</span>
                    </div>
                  </Link>
                );
              })}
            </div>
          ) : (
            <div className="p-8 text-center text-sm text-subtle flex flex-col items-center gap-3">
              <div className="w-12 h-12 rounded-full bg-surface flex items-center justify-center text-2xl">
                🔍
              </div>
              <p>No results found for &quot;{query}&quot;</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
