"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from "react";
import { usePathname, useRouter } from "next/navigation";
import {
  onAuthExpired,
  saveOriginRoute,
  takeOriginRoute,
  type AuthExpiredDetail,
} from "@/lib/auth-session";

type SessionExpiryContextValue = {
  expired: boolean;
  /** Manually trigger the expiry flow (also fired by the fetch wrapper). */
  triggerExpiry: (detail?: AuthExpiredDetail) => void;
};

const SessionExpiryContext = createContext<SessionExpiryContextValue | null>(
  null,
);

export function useSessionExpiry(): SessionExpiryContextValue {
  const ctx = useContext(SessionExpiryContext);
  if (!ctx) {
    throw new Error(
      "useSessionExpiry must be used within a SessionExpiryProvider",
    );
  }
  return ctx;
}

type Props = {
  children: ReactNode;
  /**
   * Performs the actual re-authentication (e.g. reconnect wallet / refresh
   * session). Resolves `true` on success. Defaults to a no-op success so the
   * UX can be exercised without wallet infrastructure.
   */
  onReauthenticate?: () => Promise<boolean>;
};

/**
 * Centralises detection of authentication failures and presents a single
 * re-authentication prompt (FE-70). On success the user is returned to the
 * route they started from rather than the home page, and any form drafts saved
 * via `useFormDraft` remain intact so a payment in progress is not lost.
 */
export function SessionExpiryProvider({ children, onReauthenticate }: Props) {
  const router = useRouter();
  const pathname = usePathname();
  const [expired, setExpired] = useState(false);
  const [reconnecting, setReconnecting] = useState(false);
  const [reason, setReason] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const triggerExpiry = useCallback(
    (detail?: AuthExpiredDetail) => {
      saveOriginRoute(detail?.route ?? pathname ?? "/");
      setReason(detail?.reason ?? null);
      setError(null);
      setExpired(true);
    },
    [pathname],
  );

  useEffect(() => onAuthExpired(triggerExpiry), [triggerExpiry]);

  const reconnect = useCallback(async () => {
    setReconnecting(true);
    setError(null);
    try {
      const ok = onReauthenticate ? await onReauthenticate() : true;
      if (!ok) {
        setError("Re-authentication failed. Please try again.");
        return;
      }
      setExpired(false);
      const origin = takeOriginRoute();
      if (origin) {
        router.push(origin);
      }
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setReconnecting(false);
    }
  }, [onReauthenticate, router]);

  return (
    <SessionExpiryContext.Provider value={{ expired, triggerExpiry }}>
      {children}
      {expired && (
        <div
          role="dialog"
          aria-modal="true"
          aria-label="Session expired"
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
        >
          <div className="w-full max-w-sm space-y-4 rounded-2xl border border-border-strong bg-card p-6 text-foreground shadow-xl">
            <h2 className="text-lg font-bold">Your session expired</h2>
            <p className="text-sm text-muted">
              Reconnect to continue. Your in-progress input has been saved and
              will be restored automatically.
            </p>
            {reason && <p className="text-xs text-subtle">{reason}</p>}
            {error && <p className="text-xs text-danger">{error}</p>}
            <button
              type="button"
              onClick={reconnect}
              disabled={reconnecting}
              className="w-full rounded-xl bg-primary px-4 py-3 text-sm font-bold text-white transition disabled:opacity-50"
            >
              {reconnecting ? "Reconnecting…" : "Reconnect"}
            </button>
          </div>
        </div>
      )}
    </SessionExpiryContext.Provider>
  );
}
