"use client";

import { createContext, useContext, useState, useEffect, ReactNode } from 'react';

export type WatchlistItem = {
  id: string;
  username: string;
  addedAt: Date;
};

type WatchlistContextType = {
  watchlist: WatchlistItem[];
  addToWatchlist: (id: string, username: string) => void;
  removeFromWatchlist: (id: string) => void;
  isInWatchlist: (id: string) => boolean;
  toggleWatchlist: (id: string, username: string) => void;
};

const WatchlistContext = createContext<WatchlistContextType | undefined>(undefined);

const WATCHLIST_STORAGE_KEY = 'quickex-marketplace-watchlist';

export function WatchlistProvider({ children }: { children: ReactNode }) {
  const [watchlist, setWatchlist] = useState<WatchlistItem[]>([]);

  // Load watchlist from localStorage on mount
  useEffect(() => {
    try {
      const stored = localStorage.getItem(WATCHLIST_STORAGE_KEY);
      if (stored) {
        const parsed: { id: string; username: string; addedAt: string }[] = JSON.parse(stored);
        // Convert date strings back to Date objects
        const watchlistWithDates = parsed.map((item) => ({
          ...item,
          addedAt: new Date(item.addedAt)
        }));
        setWatchlist(watchlistWithDates);
      }
    } catch (error) {
      console.error('Failed to load watchlist from localStorage:', error);
    }
  }, []);

  // Save watchlist to localStorage whenever it changes
  useEffect(() => {
    try {
      localStorage.setItem(WATCHLIST_STORAGE_KEY, JSON.stringify(watchlist));
    } catch (error) {
      console.error('Failed to save watchlist to localStorage:', error);
    }
  }, [watchlist]);

  const addToWatchlist = (id: string, username: string) => {
    setWatchlist(prev => {
      // Don't add if already exists
      if (prev.some(item => item.id === id)) return prev;

      return [...prev, {
        id,
        username,
        addedAt: new Date()
      }];
    });
  };

  const removeFromWatchlist = (id: string) => {
    setWatchlist(prev => prev.filter(item => item.id !== id));
  };

  const isInWatchlist = (id: string) => {
    return watchlist.some(item => item.id === id);
  };

  const toggleWatchlist = (id: string, username: string) => {
    if (isInWatchlist(id)) {
      removeFromWatchlist(id);
    } else {
      addToWatchlist(id, username);
    }
  };

  return (
    <WatchlistContext.Provider value={{
      watchlist,
      addToWatchlist,
      removeFromWatchlist,
      isInWatchlist,
      toggleWatchlist
    }}>
      {children}
    </WatchlistContext.Provider>
  );
}

export function useWatchlist() {
  const context = useContext(WatchlistContext);
  if (context === undefined) {
    throw new Error('useWatchlist must be used within a WatchlistProvider');
  }
  return context;
}