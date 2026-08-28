/**
 * Backend origin for browser calls. Override in `.env.local`:
 * `NEXT_PUBLIC_QUICKEX_API_URL=https://api.example.com`
 */
export const getQuickexApiBase = (): string =>
  process.env.NEXT_PUBLIC_QUICKEX_API_URL?.replace(/\/$/, "") ||
  "http://localhost:4000";

import { isAuthFailure, notifyAuthExpired } from "@/lib/auth-session";

/**
 * `fetch` wrapper that centrally detects authentication/session expiry (FE-70).
 * On a 401/403 it announces an auth-expiry event (consumed by
 * `SessionExpiryProvider`) so the app surfaces a single re-authentication
 * prompt instead of a generic API error, then still returns the response so the
 * caller can handle it.
 */
export async function fetchWithAuth(
  input: RequestInfo | URL,
  init?: RequestInit,
): Promise<Response> {
  const res = await fetch(input, init);
  if (isAuthFailure(res.status)) {
    const route =
      typeof window !== "undefined" ? window.location.pathname : undefined;
    notifyAuthExpired({ route, reason: "Your session or wallet connection expired." });
  }
  return res;
}
