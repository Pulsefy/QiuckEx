/**
 * sw-cache-strategy.ts (FE-64)
 *
 * Pure caching-strategy decisions shared between the service worker and its
 * tests. Keeping the routing logic here (rather than inline in `sw.js`) makes
 * the per-asset-class strategy explicit and unit-testable.
 */

/** Bump on any cache-shape change; old caches are purged on activate. */
export const CACHE_VERSION = "v1";

export const CACHE_NAMES = {
  shell: `quickex-shell-${CACHE_VERSION}`,
  static: `quickex-static-${CACHE_VERSION}`,
  api: `quickex-api-${CACHE_VERSION}`,
} as const;

/** The route served when a navigation fails while offline. */
export const OFFLINE_FALLBACK_URL = "/offline";

export type CacheStrategy =
  | "network-only" // never cached (payment-critical / mutations)
  | "network-first" // try network, fall back to cache
  | "cache-first" // serve cache, revalidate in background
  | "offline-fallback"; // navigation: network, else offline page

/**
 * Payment-critical reads must never be served stale, so they bypass the cache
 * entirely. Any mutation (non-GET) is also network-only.
 */
export function isPaymentCritical(pathname: string): boolean {
  return (
    /\/api\/.*(payments?|links?|transactions?|checkout|receipts?)/.test(
      pathname,
    ) || pathname.startsWith("/api/pay")
  );
}

function isStaticAsset(pathname: string): boolean {
  return (
    pathname.startsWith("/_next/static/") ||
    /\.(?:js|css|woff2?|ttf|otf|png|jpe?g|gif|svg|ico|webp|avif)$/.test(pathname)
  );
}

/**
 * Choose the caching strategy for a request.
 *
 * @param url    request URL (absolute or relative)
 * @param method HTTP method
 * @param mode   request mode; "navigate" marks a top-level navigation
 */
export function chooseStrategy(
  url: string,
  method: string = "GET",
  mode: string = "cors",
): CacheStrategy {
  if (method.toUpperCase() !== "GET") {
    return "network-only";
  }

  const pathname = safePathname(url);

  // Payment-critical API responses are never served from cache.
  if (isPaymentCritical(pathname)) {
    return "network-only";
  }

  // Other API reads: fresh-first, cache as a resilience fallback.
  if (pathname.startsWith("/api/")) {
    return "network-first";
  }

  // Hashed static assets are immutable → cache-first.
  if (isStaticAsset(pathname)) {
    return "cache-first";
  }

  // Top-level navigations fall back to the offline route when disconnected.
  if (mode === "navigate") {
    return "offline-fallback";
  }

  // App shell and everything else: fresh-first with a cached fallback.
  return "network-first";
}

function safePathname(url: string): string {
  try {
    return new URL(url, "http://localhost").pathname;
  } catch {
    return url;
  }
}
