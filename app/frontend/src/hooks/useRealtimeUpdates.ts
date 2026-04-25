"use client";

import { useState, useEffect, useCallback } from 'react';

type BidUpdate = {
  listingId: string;
  username: string;
  newBid: number;
  bidderAddress: string;
  timestamp: Date;
};

type RealtimeUpdatesHook = {
  isConnected: boolean;
  lastUpdate: Date | null;
  subscribeToListing: (listingId: string) => void;
  unsubscribeFromListing: (listingId: string) => void;
  onBidUpdate: (callback: (update: BidUpdate) => void) => () => void;
};

// Mock WebSocket simulation for real-time bid updates
class MockWebSocket {
  private listeners: ((update: BidUpdate) => void)[] = [];
  private subscribedListings: Set<string> = new Set();
  private intervalId: NodeJS.Timeout | null = null;
  private isConnected = false;

  connect() {
    this.isConnected = true;
    console.log('🔌 Connected to marketplace WebSocket');

    // Simulate periodic bid updates
    this.intervalId = setInterval(() => {
      if (this.subscribedListings.size > 0 && Math.random() < 0.3) { // 30% chance every 5 seconds
        this.simulateBidUpdate();
      }
    }, 5000);
  }

  disconnect() {
    this.isConnected = false;
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
    console.log('🔌 Disconnected from marketplace WebSocket');
  }

  subscribe(listingId: string) {
    this.subscribedListings.add(listingId);
  }

  unsubscribe(listingId: string) {
    this.subscribedListings.delete(listingId);
  }

  onBidUpdate(callback: (update: BidUpdate) => void) {
    this.listeners.push(callback);
    return () => {
      const index = this.listeners.indexOf(callback);
      if (index > -1) {
        this.listeners.splice(index, 1);
      }
    };
  }

  private simulateBidUpdate() {
    const subscribedArray = Array.from(this.subscribedListings);
    if (subscribedArray.length === 0) return;

    const randomListingId = subscribedArray[Math.floor(Math.random() * subscribedArray.length)];

    // Generate a realistic bid increase (5-20% of current bid)
    const baseIncrease = Math.floor(Math.random() * 100) + 50; // 50-150 USDC increase
    const newBid = Math.floor(Math.random() * 5000) + 1000 + baseIncrease; // Random base + increase

    const update: BidUpdate = {
      listingId: randomListingId,
      username: `user${Math.floor(Math.random() * 1000)}`, // Mock username
      newBid,
      bidderAddress: `G${Math.random().toString(36).substring(2, 15).toUpperCase()}...${Math.random().toString(36).substring(2, 6).toUpperCase()}`,
      timestamp: new Date()
    };

    this.listeners.forEach(listener => listener(update));
  }

  get connectionStatus() {
    return this.isConnected;
  }
}

// Singleton instance
const mockWebSocket = new MockWebSocket();

export function useRealtimeUpdates(): RealtimeUpdatesHook {
  const [isConnected, setIsConnected] = useState(false);
  const [lastUpdate, setLastUpdate] = useState<Date | null>(null);

  useEffect(() => {
    mockWebSocket.connect();
    setIsConnected(mockWebSocket.connectionStatus);

    return () => {
      mockWebSocket.disconnect();
    };
  }, []);

  const subscribeToListing = useCallback((listingId: string) => {
    mockWebSocket.subscribe(listingId);
  }, []);

  const unsubscribeFromListing = useCallback((listingId: string) => {
    mockWebSocket.unsubscribe(listingId);
  }, []);

  const onBidUpdate = useCallback((callback: (update: BidUpdate) => void) => {
    return mockWebSocket.onBidUpdate((update) => {
      setLastUpdate(update.timestamp);
      callback(update);
    });
  }, []);

  return {
    isConnected,
    lastUpdate,
    subscribeToListing,
    unsubscribeFromListing,
    onBidUpdate
  };
}

export type { BidUpdate };