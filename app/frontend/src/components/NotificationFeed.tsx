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
      <div className="rounded-3xl border border-dashed border-border-strong bg-card/[0.02] p-8 text-center">
        <p className="text-lg font-semibold text-foreground">{emptyTitle}</p>
        <p className="mt-2 text-sm text-muted">{emptyDescription}</p>
        {onResetFilters ? (
          <button
            type="button"
            onClick={onResetFilters}
            className="mt-5 rounded-full border border-border-strong bg-surface px-4 py-2 text-sm font-semibold text-foreground transition hover:bg-surface-strong"
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
              ? "border-border bg-card"
              : "border-brand/40 bg-brand-soft shadow-[0_20px_50px_-35px_rgba(99,102,241,0.85)]"
          }`}
        >
          <div className="flex flex-wrap items-center gap-2">
            <span
              className={`rounded-full border px-2.5 py-1 text-[11px] font-semibold uppercase tracking-[0.24em] ${CATEGORY_STYLES[notification.category]}`}
            >
              {CATEGORY_LABELS[notification.category]}
            </span>
            {!notification.readAt ? (
              <span className="rounded-full border border-border-strong bg-surface-strong px-2.5 py-1 text-[11px] font-semibold text-foreground">
                Unread
              </span>
            ) : null}
            <span className="ml-auto text-xs text-subtle">
              {formatRelativeTime(notification.createdAt)}
            </span>
          </div>

          <h3 className="mt-4 text-lg font-semibold text-foreground">
            {notification.title}
          </h3>
          <p
            className={`mt-2 text-sm ${
              compact ? "text-muted" : "text-muted"
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
              className="rounded-full bg-card px-4 py-2 text-sm font-semibold text-foreground transition hover:bg-surface-strong"
            >
              {notification.actionLabel}
            </Link>

            {!notification.readAt ? (
              <button
                type="button"
                onClick={() => onMarkAsRead(notification.id)}
                className="rounded-full border border-border-strong bg-surface px-4 py-2 text-sm font-semibold text-foreground transition hover:bg-surface-strong"
              >
                Mark as read
              </button>
            ) : (
              <span className="text-sm text-subtle">
                Already read
              </span>
            )}
          </div>
        </article>
      ))}
    </div>
  );
}
