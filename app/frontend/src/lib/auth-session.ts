/**
 * auth-session.ts (FE-70)
 *
 * Central primitives for detecting authentication/session expiry and recovering
 * from it without losing in-progress work:
 *
 * - a tiny event bus so any layer (fetch wrapper, wallet hook) can announce an
 *   auth failure and the app can respond in one place;
 * - form-draft persistence so input survives a re-authentication round trip;
 * - origin-route capture so the user returns to where they were.
 */

export type AuthExpiredDetail = {
  /** Route the user was on when the failure happened. */
  route?: string;
  /** Optional human-readable reason (never a secret/token). */
  reason?: string;
};

type Listener = (detail: AuthExpiredDetail) => void;

const listeners = new Set<Listener>();

/** Subscribe to auth-expiry events. Returns an unsubscribe function. */
export function onAuthExpired(listener: Listener): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

/** Announce that authentication has expired; notifies all subscribers. */
export function notifyAuthExpired(detail: AuthExpiredDetail = {}): void {
  for (const listener of [...listeners]) {
    listener(detail);
  }
}

/** Remove all subscribers (test helper). */
export function resetAuthListeners(): void {
  listeners.clear();
}

/** Whether an HTTP status represents an authentication/authorization failure. */
export function isAuthFailure(status: number): boolean {
  return status === 401 || status === 403;
}

const DRAFT_PREFIX = "quickex:form-draft:";
const ORIGIN_KEY = "quickex:reauth-origin";

function storage(): Storage | null {
  try {
    return typeof window !== "undefined" ? window.sessionStorage : null;
  } catch {
    return null;
  }
}

/** Persist an in-progress form draft keyed by a stable form id. */
export function saveFormDraft<T>(key: string, data: T): void {
  try {
    storage()?.setItem(DRAFT_PREFIX + key, JSON.stringify(data));
  } catch {
    /* storage may be unavailable or full — drafting is best-effort */
  }
}

/** Load a previously-saved form draft, or null if none/invalid. */
export function loadFormDraft<T>(key: string): T | null {
  const raw = storage()?.getItem(DRAFT_PREFIX + key);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as T;
  } catch {
    return null;
  }
}

/** Remove a saved form draft. */
export function clearFormDraft(key: string): void {
  storage()?.removeItem(DRAFT_PREFIX + key);
}

/** Remember the originating route to return to after re-authentication. */
export function saveOriginRoute(route: string): void {
  storage()?.setItem(ORIGIN_KEY, route);
}

/** Read and clear the saved origin route (one-shot). */
export function takeOriginRoute(): string | null {
  const s = storage();
  if (!s) return null;
  const route = s.getItem(ORIGIN_KEY);
  if (route) s.removeItem(ORIGIN_KEY);
  return route;
}
