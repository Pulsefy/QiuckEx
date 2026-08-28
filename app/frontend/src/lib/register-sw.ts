/**
 * register-sw.ts (FE-64)
 *
 * Registers the QuickEx service worker on the client. Call once from a
 * top-level client component (e.g. in a `useEffect`) after hydration. No-ops in
 * unsupported environments and in development, where a stale worker would
 * interfere with hot reload.
 */
export function registerServiceWorker(): void {
  if (typeof window === "undefined" || !("serviceWorker" in navigator)) {
    return;
  }
  if (process.env.NODE_ENV !== "production") {
    return;
  }
  window.addEventListener("load", () => {
    navigator.serviceWorker.register("/sw.js").catch((err) => {
      console.error("Service worker registration failed", err);
    });
  });
}
