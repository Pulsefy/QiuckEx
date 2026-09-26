/**
 * admin-auth.ts
 *
 * Utilities for verifying admin sessions and retrieving admin credentials
 * (cookies, JWT, or admin API keys) for protected /admin/* routes and API calls.
 */

import { cookies } from "next/headers";

/**
 * Reads admin credential from server-side cookies or environment variables.
 */
export function getAdminCredentialServer(): string | null {
  try {
    const cookieStore = cookies();
    const token =
      cookieStore.get("admin_token")?.value ??
      cookieStore.get("quickex.adminSession")?.value ??
      cookieStore.get("quickex.adminKey")?.value ??
      cookieStore.get("admin_key")?.value ??
      cookieStore.get("authorization")?.value ??
      cookieStore.get("token")?.value ??
      cookieStore.get("x-api-key")?.value;

    if (token) return token.trim();
  } catch {
    // cookies() might throw outside request context or in test environments
  }

  return (
    process.env.NEXT_PUBLIC_ADMIN_API_KEY ??
    process.env.ADMIN_API_KEY ??
    null
  );
}

/**
 * Reads admin credential from client-side cookies, sessionStorage, or env vars.
 */
export function getAdminCredentialClient(): string | null {
  if (typeof window === "undefined") {
    return getAdminCredentialServer();
  }

  try {
    const sessionToken =
      window.sessionStorage.getItem("quickex.adminSession") ??
      window.sessionStorage.getItem("quickex.adminKey");
    if (sessionToken?.trim()) return sessionToken.trim();

    const match = document.cookie.match(
      /(?:^|;)\s*(?:admin_token|quickex\.adminSession|quickex\.adminKey|admin_key|authorization|token|x-api-key)=([^;]*)/,
    );
    if (match?.[1]) {
      return decodeURIComponent(match[1]).trim();
    }
  } catch {
    // sessionStorage or document.cookie access error
  }

  return (
    process.env.NEXT_PUBLIC_ADMIN_API_KEY ??
    process.env.ADMIN_API_KEY ??
    null
  );
}

/**
 * Determines whether the current user has a valid admin session or credential.
 */
export function checkIsAdmin(): boolean {
  const credential =
    typeof window === "undefined"
      ? getAdminCredentialServer()
      : getAdminCredentialClient();

  if (!credential) return false;
  const lower = credential.toLowerCase();
  if (
    lower === "false" ||
    lower === "0" ||
    lower === "null" ||
    lower === "undefined" ||
    lower === ""
  ) {
    return false;
  }

  return true;
}
