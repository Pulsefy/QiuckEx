/*
 * QuickEx service worker (FE-64).
 *
 * Deliberate caching strategy per asset class:
 *   - payment-critical API reads  → network-only (never served stale)
 *   - other API reads             → network-first (cache as resilience)
 *   - hashed static assets        → cache-first
 *   - navigations                 → network, falling back to /offline
 *
 * Cache names are versioned (CACHE_VERSION); the activate handler purges any
 * cache that doesn't match the current version so a deploy invalidates old
 * entries without a hard reload. Mirrors src/lib/sw-cache-strategy.ts.
 */

const CACHE_VERSION = "v1";
const SHELL_CACHE = `quickex-shell-${CACHE_VERSION}`;
const STATIC_CACHE = `quickex-static-${CACHE_VERSION}`;
const API_CACHE = `quickex-api-${CACHE_VERSION}`;
const OFFLINE_URL = "/offline";
const CURRENT_CACHES = [SHELL_CACHE, STATIC_CACHE, API_CACHE];

function isPaymentCritical(pathname) {
  return (
    /\/api\/.*(payments?|links?|transactions?|checkout|receipts?)/.test(pathname) ||
    pathname.startsWith("/api/pay")
  );
}

function isStaticAsset(pathname) {
  return (
    pathname.startsWith("/_next/static/") ||
    /\.(?:js|css|woff2?|ttf|otf|png|jpe?g|gif|svg|ico|webp|avif)$/.test(pathname)
  );
}

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(SHELL_CACHE).then((cache) => cache.addAll([OFFLINE_URL, "/"])),
  );
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) =>
        Promise.all(
          keys
            .filter((key) => !CURRENT_CACHES.includes(key))
            .map((key) => caches.delete(key)),
        ),
      )
      .then(() => self.clients.claim()),
  );
});

async function networkFirst(request, cacheName) {
  try {
    const response = await fetch(request);
    const cache = await caches.open(cacheName);
    cache.put(request, response.clone());
    return response;
  } catch (err) {
    const cached = await caches.match(request);
    if (cached) return cached;
    throw err;
  }
}

async function cacheFirst(request, cacheName) {
  const cached = await caches.match(request);
  if (cached) return cached;
  const response = await fetch(request);
  const cache = await caches.open(cacheName);
  cache.put(request, response.clone());
  return response;
}

async function navigationWithOfflineFallback(request) {
  try {
    return await fetch(request);
  } catch (err) {
    const cache = await caches.open(SHELL_CACHE);
    const offline = await cache.match(OFFLINE_URL);
    if (offline) return offline;
    throw err;
  }
}

self.addEventListener("fetch", (event) => {
  const { request } = event;
  const url = new URL(request.url);

  // Only handle same-origin GETs; everything else goes straight to the network.
  if (request.method !== "GET" || url.origin !== self.location.origin) {
    return;
  }

  if (isPaymentCritical(url.pathname)) {
    // network-only — never respondWith from cache
    return;
  }

  if (url.pathname.startsWith("/api/")) {
    event.respondWith(networkFirst(request, API_CACHE));
    return;
  }

  if (isStaticAsset(url.pathname)) {
    event.respondWith(cacheFirst(request, STATIC_CACHE));
    return;
  }

  if (request.mode === "navigate") {
    event.respondWith(navigationWithOfflineFallback(request));
    return;
  }

  event.respondWith(networkFirst(request, SHELL_CACHE));
});
