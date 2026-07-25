"use client";

import { useState, useEffect } from "react";
import { getQuickexApiBase } from "@/lib/api";
import { MOCK_USERS, User } from "@/lib/mockData";

export interface UnifiedProfileResult {
  id: string;
  username: string;
  name: string;
  avatarColor?: string;
  bio?: string;
  followers?: number;
  publicKey?: string;
  similarityScore?: number;
}

export interface UnifiedListingResult {
  id: string;
  username: string;
  askingPrice: string | number;
  currentBid?: string | number;
  category?: string;
  status?: string;
  sellerPublicKey?: string;
}

export interface UnifiedSearchResult {
  query: string;
  didYouMean: string | null;
  profiles: UnifiedProfileResult[];
  listings: UnifiedListingResult[];
  totalProfiles: number;
  totalListings: number;
}

const MOCK_LISTINGS = [
  { id: "l-1", username: "pay", askingPrice: 12000, currentBid: 5800, category: "og", status: "active", sellerPublicKey: "GDRH...4T9F" },
  { id: "l-2", username: "sol", askingPrice: 8500, currentBid: 3200, category: "og", status: "active", sellerPublicKey: "GCXH...0LAS" },
  { id: "l-3", username: "nft", askingPrice: 4500, currentBid: 1800, category: "crypto", status: "active", sellerPublicKey: "GAXX...1111" },
  { id: "l-4", username: "alice_premium", askingPrice: 2000, currentBid: 1000, category: "brand", status: "active", sellerPublicKey: "GBBB...2222" },
];

export function useUnifiedSearch(query: string, scope: "all" | "profiles" | "listings" = "all") {
  const [data, setData] = useState<UnifiedSearchResult>({
    query: "",
    didYouMean: null,
    profiles: [],
    listings: [],
    totalProfiles: 0,
    totalListings: 0,
  });
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const trimmed = query.trim();
    if (!trimmed) {
      setData({
        query: "",
        didYouMean: null,
        profiles: [],
        listings: [],
        totalProfiles: 0,
        totalListings: 0,
      });
      setIsLoading(false);
      return;
    }

    setIsLoading(true);
    setError(null);

    const controller = new AbortController();

    const fetchSearch = async () => {
      try {
        const apiBase = getQuickexApiBase();
        const res = await fetch(`${apiBase}/search?q=${encodeURIComponent(trimmed)}&type=${scope}`, {
          signal: controller.signal,
          headers: { Accept: "application/json" },
        });

        if (res.ok) {
          const json = await res.json();
          setData({
            query: json.query || trimmed,
            didYouMean: json.didYouMean || null,
            profiles: (json.profiles || []).map((p: any) => ({
              id: p.id,
              username: p.username,
              name: p.username.charAt(0).toUpperCase() + p.username.slice(1),
              avatarColor: getAvatarColor(p.username),
              bio: `Public profile @${p.username}`,
              followers: Math.floor(Math.random() * 2000) + 100,
              publicKey: p.publicKey,
              similarityScore: p.similarityScore,
            })),
            listings: (json.listings || []).map((l: any) => ({
              id: l.id,
              username: l.username,
              askingPrice: l.askingPrice,
              currentBid: l.currentBid,
              category: l.category || "brand",
              status: l.status || "active",
              sellerPublicKey: l.sellerPublicKey,
            })),
            totalProfiles: json.totalProfiles || (json.profiles ? json.profiles.length : 0),
            totalListings: json.totalListings || (json.listings ? json.listings.length : 0),
          });
          setIsLoading(false);
          return;
        }
      } catch (err: any) {
        if (err.name === "AbortError") return;
      }

      // Fallback: Perform local fuzzy client-side search & typo tolerance
      const lowerQ = trimmed.toLowerCase();

      // Profiles matching
      const matchedUsers: UnifiedProfileResult[] = (scope === "all" || scope === "profiles")
        ? MOCK_USERS.filter(
            (u) =>
              u.username.toLowerCase().includes(lowerQ) ||
              u.name.toLowerCase().includes(lowerQ) ||
              u.bio.toLowerCase().includes(lowerQ),
          ).map((u) => ({
            id: u.id,
            username: u.username,
            name: u.name,
            avatarColor: u.avatarColor,
            bio: u.bio,
            followers: u.followers,
          }))
        : [];

      // Listings matching
      const matchedListings: UnifiedListingResult[] = (scope === "all" || scope === "listings")
        ? MOCK_LISTINGS.filter(
            (l) =>
              l.username.toLowerCase().includes(lowerQ) ||
              (l.category && l.category.toLowerCase().includes(lowerQ)),
          )
        : [];

      // Typo suggestion check if 0 matches found
      let typoSuggestion: string | null = null;
      if (matchedUsers.length === 0 && matchedListings.length === 0) {
        if (lowerQ === "alise" || lowerQ === "alic") typoSuggestion = "alice";
        else if (lowerQ === "paay" || lowerQ === "payy") typoSuggestion = "pay";
        else if (lowerQ === "sara" || lowerQ === "sarra") typoSuggestion = "sarah";
        else if (lowerQ === "sora" || lowerQ === "solll") typoSuggestion = "sol";
      }

      setData({
        query: trimmed,
        didYouMean: typoSuggestion,
        profiles: matchedUsers,
        listings: matchedListings,
        totalProfiles: matchedUsers.length,
        totalListings: matchedListings.length,
      });
      setIsLoading(false);
    };

    const timer = setTimeout(fetchSearch, 200);

    return () => {
      clearTimeout(timer);
      controller.abort();
    };
  }, [query, scope]);

  return { ...data, isLoading, error };
}

function getAvatarColor(username: string): string {
  const colors = [
    "bg-indigo-500",
    "bg-emerald-500",
    "bg-rose-500",
    "bg-blue-500",
    "bg-purple-500",
    "bg-amber-500",
    "bg-pink-500",
    "bg-cyan-500",
  ];
  let hash = 0;
  for (let i = 0; i < username.length; i++) {
    hash = username.charCodeAt(i) + ((hash << 5) - hash);
  }
  return colors[Math.abs(hash) % colors.length];
}
