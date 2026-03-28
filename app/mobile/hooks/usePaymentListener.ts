import { useEffect, useRef } from "react";
import { PaymentNotification } from "../components/notifications/types/notification";
import { useNotifications } from "../components/notifications/NotificationContext";

export function usePaymentListener(address?: string) {
  const { addNotification, soundEnabled } = useNotifications();
  const sinceRef = useRef<number | undefined>(undefined);
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  useEffect(() => {
    if (!address) return;

    // capture the address in a local constant so TypeScript correctly
    // narrows it for the inner async closure (avoids 'possibly undefined' errors)
    const addr = address;

    let aborted = false;

    async function poll() {
      try {
        const since = sinceRef.current;
        const url = `/payments/recent?address=${encodeURIComponent(addr)}${since ? `&since=${since}` : ""}&limit=50`;
        const base = (global as any)?.API_BASE_URL ?? "";
        const resp = await fetch(base + url);
        if (!resp.ok) return;
        const body = await resp.json();
        // eslint-disable-next-line no-console
        console.log(
          "[usePaymentListener] got",
          body?.items?.length ?? 0,
          "items",
        );
        if (!mounted.current || aborted) return;
        const items = body.items ?? [];

        // items assumed desc sorted — newest first
        for (let i = items.length - 1; i >= 0; i--) {
          const it = items[i];
          const ts = new Date(it.timestamp).getTime();
          const id =
            it.txHash ?? it.pagingToken ?? `${it.timestamp}:${it.amount}`;
          const n: PaymentNotification = {
            id,
            amount: it.amount,
            asset: it.asset,
            sender: it.from ?? undefined,
            receivedAt: ts,
            read: false,
          };

          addNotification(n);
          sinceRef.current = Math.max(sinceRef.current ?? 0, ts + 1);
        }
      } catch (e) {
        // fail silently
      }
    }

    // initial poll immediately
    void poll();
    const id = setInterval(() => void poll(), 10000);

    return () => {
      aborted = true;
      clearInterval(id);
    };
  }, [address]);
}
