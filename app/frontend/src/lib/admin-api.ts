/**
 * admin-api.ts
 *
 * Centralized helper for authenticated admin requests to the QuickEx backend.
 *
 * The admin endpoints used by the dashboard (`/admin/feature-flags`,
 * `/admin/audit`) are protected by `ApiKeyGuard` and require an `admin`-scoped
 * credential. Every admin request now goes through `adminFetch` so that:
 *
 * - the credential header is attached consistently to GET *and* PATCH calls;
 * - a missing credential fails loudly (throws `AdminCredentialError`) *before*
 *   the network call, instead of silently issuing an unauthenticated request
 *   that surfaces as a confusing 401/403 or an empty list;
 * - the audited actor is no longer supplied by the client — the backend
 *   derives it from the validated API key, so the spoofable `x-admin-actor`
 *   header is not sent from here.
 *
 * The credential comes from the same sources the rest of the admin surface
 * already authenticates with: the admin session token issued at sign-in, the
 * cookie / legacy session-storage credential the server-side `checkIsAdmin`
 * gate accepts, and finally the build-time `NEXT_PUBLIC_ADMIN_API_KEY` used for
 * local development. Sharing the resolution with `getAdminCredentialClient`
 * keeps the client panels in sync with `app/admin/layout.tsx` — otherwise a
 * cookie-authenticated admin would render the console but every panel would
 * fail with `AdminCredentialError`.
 */

import { getAdminCredentialClient } from "@/lib/admin-auth";

const ADMIN_SESSION_TOKEN_KEY = "quickex:admin-session-token";

/** Raised when an admin request is attempted without a usable credential. */
export class AdminCredentialError extends Error {
  constructor() {
    super(
      "No admin credential is available. Sign in as an administrator, or configure an admin API key, before using admin tools.",
    );
    this.name = "AdminCredentialError";
  }
}

/** Read a short-lived admin session token, if one was issued at sign-in. */
function readSessionToken(): string | null {
  if (typeof window === "undefined") return null;
  try {
    const token = window.sessionStorage.getItem(ADMIN_SESSION_TOKEN_KEY);
    return token && token.trim() !== "" ? token.trim() : null;
  } catch {
    return null;
  }
}

/**
 * Resolve the credential used for admin requests.
 *
 * Precedence:
 * 1. the rotatable admin session token issued at sign-in (never embedded in
 *    the bundle);
 * 2. the admin cookie / legacy session-storage credential resolved by
 *    `getAdminCredentialClient` — the same credential the server-side admin
 *    gate accepts;
 * 3. `NEXT_PUBLIC_ADMIN_API_KEY`, as a non-browser (SSR / test) fallback.
 */
export function getAdminCredential(): string | null {
  const sessionToken = readSessionToken();
  if (sessionToken) return sessionToken;

  const clientCredential = getAdminCredentialClient();
  if (clientCredential && clientCredential.trim() !== "") {
    return clientCredential.trim();
  }

  // `getAdminCredentialClient` short-circuits outside the browser, so keep an
  // explicit env fallback for SSR and node-based tests.
  const apiKey =
    process.env.NEXT_PUBLIC_ADMIN_API_KEY ?? process.env.ADMIN_API_KEY;
  return apiKey && apiKey.trim() !== "" ? apiKey.trim() : null;
}

/** Store (or clear) the admin session token issued by the backend at sign-in. */
export function setAdminSessionToken(token: string | null): void {
  if (typeof window === "undefined") return;
  try {
    if (token && token.trim() !== "") {
      window.sessionStorage.setItem(ADMIN_SESSION_TOKEN_KEY, token.trim());
    } else {
      window.sessionStorage.removeItem(ADMIN_SESSION_TOKEN_KEY);
    }
  } catch {
    /* storage may be unavailable; the next request still fails loudly */
  }
}

/**
 * `fetch` wrapper for admin endpoints. Attaches the admin credential and throws
 * `AdminCredentialError` when none is available so the UI can render an
 * explicit auth error rather than silently failing.
 */
export async function adminFetch(
  input: string,
  init: RequestInit = {},
): Promise<Response> {
  const credential = getAdminCredential();
  if (!credential) {
    throw new AdminCredentialError();
  }

  const headers = new Headers(init.headers);
  headers.set("x-api-key", credential);
  if (!headers.has("Accept")) {
    headers.set("Accept", "application/json");
  }

  return fetch(input, { ...init, headers });
}
