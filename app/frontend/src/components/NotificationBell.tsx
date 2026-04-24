"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { NotificationFeed } from "@/components/NotificationFeed";
import {
  filterNotifications,
  type NotificationReadState,
} from "@/lib/notifications";
import { useNotificationCenter } from "@/components/NotificationCenterProvider";

export function NotificationBell() {
  const pathname = usePathname();
  const { notifications, unreadCount, markAsRead, markAllAsRead } =
    useNotificationCenter();
  const [isOpen, setIsOpen] = useState(false);
  const [readState, setReadState] = useState<Exclude<
    NotificationReadState,
    "read"
  >>("all");
  const panelRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    setIsOpen(false);
  }, [pathname]);

  useEffect(() => {
    if (!isOpen) {
      return;
    }

    const handlePointerDown = (event: PointerEvent) => {
      if (
        panelRef.current &&
        !panelRef.current.contains(event.target as Node)
      ) {
        setIsOpen(false);
      }
    };

    const handleEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setIsOpen(false);
      }
    };

    window.addEventListener("pointerdown", handlePointerDown);
    window.addEventListener("keydown", handleEscape);

    return () => {
      window.removeEventListener("pointerdown", handlePointerDown);
      window.removeEventListener("keydown", handleEscape);
    };
  }, [isOpen]);

  const visibleNotifications = useMemo(
    () => filterNotifications(notifications, "all", readState).slice(0, 4),
    [notifications, readState],
  );

  return (
    <div className="relative" ref={panelRef}>
      <button
        type="button"
        aria-expanded={isOpen}
        aria-controls="quickex-notification-panel"
        aria-label={
          unreadCount > 0
            ? `Open notifications. ${unreadCount} unread.`
            : "Open notifications."
        }
        onClick={() => setIsOpen((currentValue) => !currentValue)}
        className="relative flex h-11 items-center justify-center rounded-full border border-white/10 bg-white/5 px-3.5 text-sm font-semibold text-white transition hover:bg-white/10"
      >
        <span aria-hidden="true">Inbox</span>
        {unreadCount > 0 ? (
          <span className="absolute -right-1 -top-1 min-w-6 rounded-full bg-indigo-500 px-1.5 py-0.5 text-[11px] font-semibold text-white">
            {unreadCount}
          </span>
        ) : null}
      </button>

      {isOpen ? (
        <div
          id="quickex-notification-panel"
          className="absolute right-0 top-14 z-50 w-[min(26rem,calc(100vw-2rem))] rounded-[2rem] border border-white/10 bg-neutral-950/98 p-5 shadow-[0_30px_80px_-25px_rgba(15,23,42,0.9)] backdrop-blur"
        >
          <div className="flex items-start justify-between gap-4">
            <div>
              <p className="text-lg font-semibold text-white">Notifications</p>
              <p className="mt-1 text-sm text-neutral-300">
                Stay on top of payments, escrows, and system updates.
              </p>
            </div>
            <button
              type="button"
              onClick={() => setIsOpen(false)}
              className="rounded-full border border-white/10 bg-white/5 px-3 py-1.5 text-xs font-semibold text-neutral-100 transition hover:bg-white/10"
            >
              Close
            </button>
          </div>

          <div className="mt-4 flex items-center gap-2">
            {(["all", "unread"] as const).map((option) => (
              <button
                key={option}
                type="button"
                onClick={() => setReadState(option)}
                className={`rounded-full px-3.5 py-2 text-sm font-semibold transition ${
                  readState === option
                    ? "bg-white text-neutral-950"
                    : "border border-white/10 bg-white/5 text-neutral-100 hover:bg-white/10"
                }`}
              >
                {option === "all" ? "All" : "Unread"}
              </button>
            ))}

            <button
              type="button"
              onClick={() => markAllAsRead()}
              disabled={unreadCount === 0}
              className="ml-auto rounded-full border border-white/10 bg-white/5 px-3.5 py-2 text-sm font-semibold text-neutral-100 transition hover:bg-white/10 disabled:cursor-not-allowed disabled:opacity-50"
            >
              Mark all read
            </button>
          </div>

          <div className="mt-5 max-h-[28rem] overflow-y-auto pr-1">
            <NotificationFeed
              notifications={visibleNotifications}
              emptyTitle="Nothing new right now"
              emptyDescription="Everything in this view has already been handled."
              onMarkAsRead={markAsRead}
              onNavigate={() => setIsOpen(false)}
              compact
            />
          </div>

          <div className="mt-5 flex items-center justify-between border-t border-white/10 pt-4">
            <span className="text-sm text-neutral-400">
              {unreadCount} unread
            </span>
            <Link
              href="/notifications"
              className="rounded-full bg-indigo-500 px-4 py-2 text-sm font-semibold text-white transition hover:bg-indigo-400"
            >
              Open inbox
            </Link>
          </div>
        </div>
      ) : null}
    </div>
  );
}
