import { getWalletSession } from "./wallet-session";
import type { BackendMetadata } from "../src/config/environment";

export interface AccountContext {
  publicKey: string;
}

export interface BootstrapResponse {
  metadata: BackendMetadata;
  unreadCount: number;
  featureFlags: Record<string, boolean>;
  accountContext: AccountContext | null;
  /**
   * Runtime-configured whitelist of assets the backend can swap FROM.
   * Sourced from the backend so it stays in sync without an app release.
   * May be absent on older backends, in which case the client falls back
   * to a conservative built-in default (see services/swappable-assets).
   */
  swappableAssets?: string[];
}

/**
 * Fetches the session bootstrap data including environment metadata,
 * feature flags, unread counts, and account context.
 * 
 * If a wallet session exists, it attaches the public key as a Bearer token
 * to fetch authenticated data (e.g. unread count). Otherwise, it fetches
 * guest data.
 */
export async function fetchSessionBootstrap(apiUrl: string): Promise<BootstrapResponse> {
  const session = await getWalletSession();
  const headers: Record<string, string> = {
    Accept: "application/json",
    "Content-Type": "application/json",
  };
  
  if (session?.publicKey) {
    // We use the publicKey as a simple Bearer token for the session.
    // In a real app, this might be a JWT or a signed payload.
    headers["Authorization"] = `Bearer ${session.publicKey}`;
  }
  
  const baseUrl = apiUrl.replace(/\/$/, "");
  const response = await fetch(`${baseUrl}/session/bootstrap`, {
    method: "GET",
    headers,
  });
  
  if (!response.ok) {
    let message = `Bootstrap failed with status ${response.status}`;
    try {
      const body = await response.json() as { message?: string };
      if (body.message) message = body.message;
    } catch {
      // keep status-code message
    }
    throw new Error(message);
  }
  
  return response.json() as Promise<BootstrapResponse>;
}
