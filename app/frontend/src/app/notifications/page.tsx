"use client";

import Link from "next/link";
import { Suspense, useMemo } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { NotificationFeed } from "@/components/NotificationFeed";
import { useNotificationCenter } from "@/components/NotificationCenterProvider";
import {
  CATEGORY_LABELS,
  filterNotifications,
  type NotificationCategory,
  type NotificationReadState,
} from "@/lib/notifications";
import { NetworkBadge } from "@/components/NetworkBadge";

const CATEGORY_OPTIONS = [
  { value: "all", label: "All" },
  { value: "payments", label: CATEGORY_LABELS.payments },
  { value: "escrows", label: CATEGORY_LABELS.escrows },
  { value: "system", label: CATEGORY_LABELS.system },
] as const;

const READ_STATE_OPTIONS = [
  { value: "all", label: "Everything" },
  { value: "unread", label: "Unread" },
  { value: "read", label: "Read" },
] as const;

function normalizeCategory(
  value: string | null,
): NotificationCategory | "all" {
  if (value === "payments" || value === "escrows" || value === "system") {
    return value;
  }

  return "all";
}

function normalizeReadState(value: string | null): NotificationReadState {
  if (value === "unread" || value === "read") {
    return value;
  }

  return "all";
}

function NotificationsPageContent() {
  const pathname = usePathname();
  const router = useRouter();
  const searchParams = useSearchParams();
  const { notifications, unreadCount, markAsRead, markAllAsRead } =
    useNotificationCenter();

  const activeCategory = normalizeCategory(searchParams.get("category"));
  const activeReadState = normalizeReadState(searchParams.get("status"));

  const filteredNotifications = useMemo(
    () => filterNotifications(notifications, activeCategory, activeReadState),
    [activeCategory, activeReadState, notifications],
  );

  const counts = useMemo(
    () => ({
      payments: filterNotifications(notifications, "payments", "all").length,
      escrows: filterNotifications(notifications, "escrows", "all").length,
      system: filterNotifications(notifications, "system", "all").length,
    }),
    [notifications],
  );

  const updateFilters = (next: {
    category?: NotificationCategory | "all";
    status?: NotificationReadState;
  }) => {
    const params = new URLSearchParams(searchParams.toString());
    const nextCategory = next.category ?? activeCategory;
    const nextStatus = next.status ?? activeReadState;

    if (nextCategory === "all") {
      params.delete("category");
    } else {
      params.set("category", nextCategory);
    }

    if (nextStatus === "all") {
      params.delete("status");
    } else {
      params.set("status", nextStatus);
    }

    const query = params.toString();
    router.replace(query ? `${pathname}?${query}` : pathname, {
      scroll: false,
    });
  };

  return (
    <div className="relative min-h-screen text-white">
      <NetworkBadge />

      <div className="fixed left-[-20%] top-[-15%] h-[24rem] w-[24rem] rounded-full bg-indigo-500/15 blur-[120px]" />
      <div className="fixed bottom-[-18%] right-[-12%] h-[22rem] w-[22rem] rounded-full bg-emerald-500/10 blur-[120px]" />

      <div className="relative z-10 mx-auto max-w-6xl">
        <header className="rounded-[2rem] border border-white/10 bg-white/[0.04] p-8 shadow-[0_30px_80px_-30px_rgba(15,23,42,0.85)] backdrop-blur">
          <nav className="flex flex-wrap items-center gap-2 text-xs font-semibold uppercase tracking-[0.24em] text-neutral-400">
            <Link href="/" className="transition hover:text-white">
              QuickEx
            </Link>
            <span>/</span>
            <span className="text-neutral-100">Notifications</span>
          </nav>

          <div className="mt-6 flex flex-col gap-6 lg:flex-row lg:items-end lg:justify-between">
            <div>
              <h1 className="text-4xl font-semibold tracking-tight text-white sm:text-5xl">
                Notification Center
              </h1>
              <p className="mt-3 max-w-2xl text-base text-neutral-200">
                Review updates, jump directly into the right payment or escrow
                context, and keep your inbox clean without losing anything on
                refresh.
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-3">
              <Link
                href="/dashboard"
                className="rounded-full border border-white/10 bg-white/5 px-4 py-2.5 text-sm font-semibold text-neutral-100 transition hover:bg-white/10"
              >
                Back to dashboard
              </Link>
              <button
                type="button"
                onClick={() => markAllAsRead()}
                disabled={unreadCount === 0}
                className="rounded-full bg-white px-4 py-2.5 text-sm font-semibold text-neutral-950 transition hover:bg-neutral-200 disabled:cursor-not-allowed disabled:opacity-50"
              >
                Mark all as read
              </button>
            </div>
          </div>

          <div className="mt-8 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <div className="rounded-3xl border border-white/10 bg-neutral-950/60 p-5">
              <p className="text-sm text-neutral-400">Unread</p>
              <p className="mt-2 text-3xl font-semibold text-white">
                {unreadCount}
              </p>
            </div>
            <div className="rounded-3xl border border-white/10 bg-neutral-950/60 p-5">
              <p className="text-sm text-neutral-400">Payments</p>
              <p className="mt-2 text-3xl font-semibold text-white">
                {counts.payments}
              </p>
            </div>
            <div className="rounded-3xl border border-white/10 bg-neutral-950/60 p-5">
              <p className="text-sm text-neutral-400">Escrows</p>
              <p className="mt-2 text-3xl font-semibold text-white">
                {counts.escrows}
              </p>
            </div>
            <div className="rounded-3xl border border-white/10 bg-neutral-950/60 p-5">
              <p className="text-sm text-neutral-400">System</p>
              <p className="mt-2 text-3xl font-semibold text-white">
                {counts.system}
              </p>
            </div>
          </div>
        </header>

        <section className="mt-8 rounded-[2rem] border border-white/10 bg-white/[0.03] p-8 backdrop-blur">
          <div className="flex flex-col gap-6 lg:flex-row lg:items-end lg:justify-between">
            <div className="space-y-3">
              <div>
                <p className="text-sm font-semibold text-neutral-300">
                  Category
                </p>
                <div className="mt-3 flex flex-wrap gap-2">
                  {CATEGORY_OPTIONS.map((option) => (
                    <button
                      key={option.value}
                      type="button"
                      onClick={() => updateFilters({ category: option.value })}
                      className={`rounded-full px-4 py-2 text-sm font-semibold transition ${
                        activeCategory === option.value
                          ? "bg-white text-neutral-950"
                          : "border border-white/10 bg-white/5 text-neutral-100 hover:bg-white/10"
                      }`}
                    >
                      {option.label}
                    </button>
                  ))}
                </div>
              </div>

              <div>
                <p className="text-sm font-semibold text-neutral-300">
                  Read state
                </p>
                <div className="mt-3 flex flex-wrap gap-2">
                  {READ_STATE_OPTIONS.map((option) => (
                    <button
                      key={option.value}
                      type="button"
                      onClick={() => updateFilters({ status: option.value })}
                      className={`rounded-full px-4 py-2 text-sm font-semibold transition ${
                        activeReadState === option.value
                          ? "bg-indigo-500 text-white"
                          : "border border-white/10 bg-white/5 text-neutral-100 hover:bg-white/10"
                      }`}
                    >
                      {option.label}
                    </button>
                  ))}
                </div>
              </div>
            </div>

            {(activeCategory !== "all" || activeReadState !== "all") ? (
              <button
                type="button"
                onClick={() => updateFilters({ category: "all", status: "all" })}
                className="rounded-full border border-white/10 bg-white/5 px-4 py-2.5 text-sm font-semibold text-neutral-100 transition hover:bg-white/10"
              >
                Reset filters
              </button>
            ) : null}
          </div>

          <div className="mt-8">
            <NotificationFeed
              notifications={filteredNotifications}
              emptyTitle="No notifications match these filters"
              emptyDescription="Try a different category or switch back to everything to see the full inbox."
              onMarkAsRead={markAsRead}
              onResetFilters={() =>
                updateFilters({ category: "all", status: "all" })
              }
            />
          </div>
        </section>
      </div>
    </div>
  );
}

export default function NotificationsPage() {
  return (
    <Suspense
      fallback={
        <div className="relative min-h-screen text-white">
          <div className="mx-auto max-w-6xl rounded-[2rem] border border-white/10 bg-white/[0.04] p-8 text-neutral-200 backdrop-blur">
            Loading notifications...
          </div>
        </div>
      }
    >
      <NotificationsPageContent />
    </Suspense>
  );
}
