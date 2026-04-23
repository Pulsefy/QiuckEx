"use client";

import Link from "next/link";
import {
  CATEGORY_LABELS,
  CATEGORY_STYLES,
  formatRelativeTime,
  type StoredNotification,
} from "@/lib/notifications";

type NotificationFeedProps = {
  notifications: StoredNotification[];
  emptyTitle: string;
  emptyDescription: string;
  onMarkAsRead: (id: string) => void;
  onNavigate?: () => void;
  onResetFilters?: () => void;
  compact?: boolean;
};

export function NotificationFeed({
  notifications,
  emptyTitle,
  emptyDescription,
  onMarkAsRead,
  onNavigate,
  onResetFilters,
  compact = false,
}: NotificationFeedProps) {
  if (notifications.length === 0) {
    return (
      <div className="rounded-3xl border border-dashed border-white/10 bg-white/[0.02] p-8 text-center">
        <p className="text-lg font-semibold text-white">{emptyTitle}</p>
        <p className="mt-2 text-sm text-neutral-300">{emptyDescription}</p>
        {onResetFilters ? (
          <button
            type="button"
            onClick={onResetFilters}
            className="mt-5 rounded-full border border-white/10 bg-white/5 px-4 py-2 text-sm font-semibold text-neutral-100 transition hover:bg-white/10"
          >
            Show everything
          </button>
        ) : null}
      </div>
    );
  }

  return (
    <div className={compact ? "space-y-3" : "space-y-4"}>
      {notifications.map((notification) => (
        <article
          key={notification.id}
          className={`rounded-3xl border p-4 transition ${
            notification.readAt
              ? "border-white/8 bg-white/[0.03]"
              : "border-indigo-400/20 bg-indigo-500/[0.08] shadow-[0_20px_50px_-35px_rgba(99,102,241,0.85)]"
          }`}
        >
          <div className="flex flex-wrap items-center gap-2">
            <span
              className={`rounded-full border px-2.5 py-1 text-[11px] font-semibold uppercase tracking-[0.24em] ${CATEGORY_STYLES[notification.category]}`}
            >
              {CATEGORY_LABELS[notification.category]}
            </span>
            {!notification.readAt ? (
              <span className="rounded-full bg-white/10 px-2.5 py-1 text-[11px] font-semibold text-white">
                Unread
              </span>
            ) : null}
            <span className="ml-auto text-xs text-neutral-400">
              {formatRelativeTime(notification.createdAt)}
            </span>
          </div>

          <h3 className="mt-4 text-lg font-semibold text-white">
            {notification.title}
          </h3>
          <p
            className={`mt-2 text-sm ${
              compact ? "text-neutral-300" : "text-neutral-200"
            }`}
          >
            {notification.description}
          </p>

          <div className="mt-5 flex flex-wrap items-center gap-3">
            <Link
              href={notification.href}
              onClick={() => {
                onMarkAsRead(notification.id);
                onNavigate?.();
              }}
              className="rounded-full bg-white px-4 py-2 text-sm font-semibold text-neutral-950 transition hover:bg-neutral-200"
            >
              {notification.actionLabel}
            </Link>

            {!notification.readAt ? (
              <button
                type="button"
                onClick={() => onMarkAsRead(notification.id)}
                className="rounded-full border border-white/10 bg-white/5 px-4 py-2 text-sm font-semibold text-neutral-100 transition hover:bg-white/10"
              >
                Mark as read
              </button>
            ) : (
              <span className="text-sm text-neutral-400">
                Already read
              </span>
            )}
          </div>
        </article>
      ))}
    </div>
  );
}
