"use client";

import { useState, useEffect, useRef } from "react";
import Link from "next/link";
import { User, MOCK_USERS } from "@/lib/mockData";

export function SearchBar() {
  const [query, setQuery] = useState("");
  const [isOpen, setIsOpen] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [results, setResults] = useState<User[]>([]);
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
    if (!query.trim()) {
      setResults([]);
      return;
    }

    setIsLoading(true);
    setIsOpen(true);

    const timer = setTimeout(() => {
      const lowerQuery = query.toLowerCase();
      const filtered = MOCK_USERS.filter(user => 
        user.username.toLowerCase().includes(lowerQuery) || 
        user.name.toLowerCase().includes(lowerQuery) ||
        user.bio.toLowerCase().includes(lowerQuery)
      );
      setResults(filtered.slice(0, 5)); // max 5 results
      setIsLoading(false);
    }, 300); // simulate network delay

    return () => clearTimeout(timer);
  }, [query]);

  return (
    <div className="relative w-full" ref={dropdownRef}>
      <div className="relative flex items-center">
        <svg className="absolute left-3 w-4 h-4 text-subtle" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
        </svg>
        <input 
          type="text" 
          placeholder="Search global profiles..." 
          className="w-full bg-card/50 border border-border-strong rounded-full pl-10 pr-10 py-2 text-sm text-foreground placeholder-neutral-500 focus:outline-none focus:border-indigo-500/50 focus:ring-1 focus:ring-indigo-500/50 transition-all font-medium"
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
            className="absolute right-3 text-subtle hover:text-foreground transition"
            onClick={() => setQuery("")}
            title="Clear"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        )}
      </div>

      {isOpen && query.trim() && (
        <div className="absolute top-full lg:left-0 -left-10 lg:w-full w-[120%] mt-2 bg-card border border-border-strong rounded-2xl shadow-2xl overflow-hidden z-50 animate-in fade-in slide-in-from-top-2 duration-200">
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
          ) : results.length > 0 ? (
            <div className="flex flex-col py-2">
              <div className="px-4 py-2 text-xs font-semibold text-subtle uppercase tracking-wider mb-1">
                Profiles
              </div>
              {results.map((user) => (
                <Link 
                  key={user.id} 
                  href={`/profile/${user.username}`} 
                  className="flex items-center gap-4 px-4 py-2 hover:bg-surface transition group"
                  onClick={() => setIsOpen(false)}
                >
                  <div className={`w-10 h-10 rounded-full flex items-center justify-center font-bold text-sm shadow-inner ${user.avatarColor}`}>
                    {user.name.charAt(0)}
                  </div>
                  <div className="flex-1 flex flex-col items-start overflow-hidden">
                    <span className="text-sm font-semibold text-foreground group-hover:text-indigo-400 transition-colors truncate">{user.name}</span>
                    <span className="text-xs text-subtle truncate">@{user.username}</span>
                  </div>
                </Link>
              ))}
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
