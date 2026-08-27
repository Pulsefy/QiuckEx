"use client";

import { useEffect, useState } from "react";
import { getQuickexApiBase } from "@/lib/api";

export type PublicProfile = {
  id: string;
  username: string;
  publicKey: string;
  similarityScore?: number;
  transactionVolume?: number;
  transactionCount?: number;
  lastActiveAt: string;
  createdAt: string;
};

type DiscoveryResponse = {
  creators: PublicProfile[];
};

type RecentlyActiveResponse = {
  users: PublicProfile[];
};

type SearchResponse = {
  results?: Array<PublicProfile & { kind?: "profile" | "listing" }>;
  profiles?: PublicProfile[];
};

const getErrorMessage = (error: unknown, fallback: string): string =>
  error instanceof Error ? error.message : fallback;

export function useDiscoveryProfiles() {
  const [trending, setTrending] = useState<PublicProfile[]>([]);
  const [recent, setRecent] = useState<PublicProfile[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    const load = async () => {
      try {
        const [trendingResponse, recentResponse] = await Promise.all([
          fetch(`${getQuickexApiBase()}/username/trending?limit=8`, {
            signal: controller.signal,
          }),
          fetch(`${getQuickexApiBase()}/username/recently-active?limit=8`, {
            signal: controller.signal,
          }),
        ]);

        if (!trendingResponse.ok || !recentResponse.ok) {
          throw new Error("Unable to load discovery profiles.");
        }

        const [trendingPayload, recentPayload] = await Promise.all([
          trendingResponse.json() as Promise<DiscoveryResponse>,
          recentResponse.json() as Promise<RecentlyActiveResponse>,
        ]);
        setTrending(trendingPayload.creators ?? []);
        setRecent(recentPayload.users ?? []);
        setError(null);
      } catch (loadError) {
        if (!controller.signal.aborted) {
          setTrending([]);
          setRecent([]);
          setError(getErrorMessage(loadError, "Unable to load discovery profiles."));
        }
      } finally {
        if (!controller.signal.aborted) setIsLoading(false);
      }
    };

    void load();
    return () => controller.abort();
  }, []);

  return { trending, recent, isLoading, error };
}

export function useProfileSearch(query: string) {
  const [results, setResults] = useState<PublicProfile[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const normalizedQuery = query.trim();
    if (!normalizedQuery) {
      setResults([]);
      setError(null);
      setIsLoading(false);
      return;
    }

    if (normalizedQuery.length < 2) {
      setResults([]);
      setError("Enter at least 2 characters to search.");
      setIsLoading(false);
      return;
    }

    const controller = new AbortController();
    const timer = window.setTimeout(async () => {
      setIsLoading(true);
      setError(null);

      try {
        const response = await fetch(
          `${getQuickexApiBase()}/username/search?query=${encodeURIComponent(normalizedQuery)}&limit=5`,
          { signal: controller.signal },
        );
        if (!response.ok) throw new Error("Unable to search profiles.");

        const payload = (await response.json()) as SearchResponse;
        const profiles = payload.results
          ? payload.results.filter((result) => result.kind === "profile")
          : payload.profiles ?? [];
        setResults(profiles.slice(0, 5));
      } catch (searchError) {
        if (!controller.signal.aborted) {
          setResults([]);
          setError(getErrorMessage(searchError, "Unable to search profiles."));
        }
      } finally {
        if (!controller.signal.aborted) setIsLoading(false);
      }
    }, 300);

    return () => {
      window.clearTimeout(timer);
      controller.abort();
    };
  }, [query]);

  return { results, isLoading, error };
}