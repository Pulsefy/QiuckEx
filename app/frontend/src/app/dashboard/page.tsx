"use client";

import { Suspense, useEffect, useMemo, useState, useCallback } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import AnalyticsDashboard from "@/components/AnalyticsDashboard";
import { NetworkBadge } from "@/components/NetworkBadge";
import { useApi } from "@/hooks/useApi";
import { fetchAnalytics, type AnalyticsData } from "@/hooks/analyticsApi";
import {
  fetchUserBids,
  fetchUserListings,
  formatCountdown,
  type UserBid,
  type UserListing,
} from "@/hooks/marketplaceApi";
import {
  fetchActivityFeed,
  type ActivityFeedItem,
} from "@/hooks/activityFeedApi";
import {
  filterActivityItems,
  hasActiveFilters,
  type ActivityFilterState,
} from "@/lib/activityFilters";
import { PaymentHistoryFilters } from "@/components/PaymentHistoryFilters";

type DashboardResponse = {
  items: ActivityFeedItem[];
  degraded: boolean;
};

function toAnchorId(prefix: string, value: string) {
  return `${prefix}-${value.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`;
}

function getStatusClasses(status: ActivityFeedItem["status"]) {
  switch (status) {
    case "Pending":
      return "border-amber-300/40 bg-amber-400/10 text-warning";
    case "Settled":
      return "border-emerald-300/40 bg-emerald-400/10 text-success";
    default:
      return "border-slate-300/40 bg-slate-400/10 text-muted";
  }
}

function shortAddress(key: string): string {
  if (key.length <= 12) return key;
  return `${key.slice(0, 6)}…${key.slice(-4)}`;
}

const FOCUS_RING_CLASS =
  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300 focus-visible:ring-offset-2 focus-visible:ring-offset-background";

function formatCurrency(val: number): string {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  }).format(val);
}

function DashboardContent() {
  const searchParams = useSearchParams();
  const { data, error, loading, callApi } = useApi<DashboardResponse>();
  const [userBids, setUserBids] = useState<UserBid[]>([]);
  const [userListings, setUserListings] = useState<UserListing[]>([]);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const [feedRetryCount, setFeedRetryCount] = useState(0);

  const [metricsData, setMetricsData] = useState<AnalyticsData | null>(null);
  const [metricsLoading, setMetricsLoading] = useState(true);
  const [metricsError, setMetricsError] = useState<string | null>(null);
  const [activityFilters, setActivityFilters] = useState<ActivityFilterState>({
    query: "",
    status: "All",
    asset: "All",
  });

  const loadMetrics = useCallback(async () => {
    setMetricsLoading(true);
    setMetricsError(null);
    try {
      const data = await fetchAnalytics("30d");
      setMetricsData(data);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Failed to load backend metrics";
      setMetricsError(message);
    } finally {
      setMetricsLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadMetrics();
  }, [loadMetrics]);

  useEffect(() => {
    void callApi(() => fetchActivityFeed(20));
    void fetchUserBids().then(setUserBids);
    void fetchUserListings().then(setUserListings);
  }, [callApi, feedRetryCount]);

  useEffect(() => {
    if (!statusMessage) {
      return;
    }

    const timer = window.setTimeout(() => setStatusMessage(null), 3200);
    return () => window.clearTimeout(timer);
  }, [statusMessage]);

  const highlightedTransaction = searchParams.get("tx");
  const highlightedBid = searchParams.get("bid");
  const highlightedListing = searchParams.get("listing");
  const highlightedPanel = searchParams.get("panel");

  const focusTargetId = useMemo(() => {
    if (highlightedTransaction) {
      return toAnchorId("transaction", highlightedTransaction);
    }

    if (highlightedBid) {
      return toAnchorId("bid", highlightedBid);
    }

    if (highlightedListing) {
      return toAnchorId("listing", highlightedListing);
    }

    if (highlightedPanel === "activity") {
      return "dashboard-activity";
    }

    if (highlightedPanel === "bids") {
      return "dashboard-bids";
    }

    if (highlightedPanel === "listings") {
      return "dashboard-listings";
    }

    return null;
  }, [
    highlightedBid,
    highlightedListing,
    highlightedPanel,
    highlightedTransaction,
  ]);

  useEffect(() => {
    if (!focusTargetId) {
      return;
    }

    const timer = window.setTimeout(() => {
      const target = document.getElementById(focusTargetId);
      target?.scrollIntoView({
        behavior: "smooth",
        block: "center",
      });
      target?.focus();
    }, 180);

    return () => window.clearTimeout(timer);
  }, [focusTargetId, userBids.length, userListings.length, data?.items.length]);

  const spotlightMessage = useMemo(() => {
    if (highlightedTransaction) {
      return `Opened from notifications: transaction ${highlightedTransaction}.`;
    }

    if (highlightedBid) {
      return `Opened from notifications: active bid on @${highlightedBid}.`;
    }

    if (highlightedListing) {
      return `Opened from notifications: listing activity for @${highlightedListing}.`;
    }

    return null;
  }, [highlightedBid, highlightedListing, highlightedTransaction]);

  const assetOptions = useMemo(
    () => [
      "All",
      ...Array.from(new Set((data?.items ?? []).map((item) => item.asset))).sort(),
    ],
    [data?.items],
  );

  const filteredActivityItems = useMemo(
    () => filterActivityItems(data?.items ?? [], activityFilters),
    [activityFilters, data?.items],
  );

  const hasActivityFilters = hasActiveFilters(activityFilters);

  const clearActivityFilters = () => {
    setActivityFilters({ query: "", status: "All", asset: "All" });
  };

  const handleRetry = () => {
    setFeedRetryCount((prev) => prev + 1);
  };

  if (loading) {
    return (
      <div className="flex min-h-[60vh] items-center justify-center">
        <div className="text-center">
          <div className="mb-4 h-8 w-8 animate-spin rounded-full border-2 border-indigo-500 border-t-transparent mx-auto" />
          <p className="text-muted">Loading dashboard...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex min-h-[60vh] items-center justify-center">
        <div className="max-w-md text-center">
          <div className="mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-red-500/10 mx-auto">
            <svg
              className="h-8 w-8 text-danger"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              strokeWidth={1.5}
              aria-hidden="true"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126ZM12 15.75h.007v.008H12v-.008Z"
              />
            </svg>
          </div>
          <h3 className="text-lg font-semibold text-foreground">
            Failed to load dashboard
          </h3>
          <p className="mt-2 text-sm text-muted">{error}</p>
          <button
            type="button"
            onClick={handleRetry}
            className="mt-6 rounded-xl bg-indigo-500 px-5 py-2.5 text-sm font-semibold text-white shadow-lg transition hover:bg-indigo-400"
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="relative min-h-screen text-foreground">
      <a
        href="#dashboard-main"
        className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-50 focus:rounded-lg focus:bg-indigo-500 focus:px-3 focus:py-2 focus:text-sm focus:font-semibold focus:text-white"
      >
        Skip to dashboard content
      </a>
      <NetworkBadge />

      <div className="fixed left-[-30%] top-[-20%] h-[60%] w-[60%] rounded-full bg-indigo-500/10 blur-[120px]" />
      <div className="fixed bottom-[-20%] right-[-30%] h-[50%] w-[50%] rounded-full bg-purple-500/5 blur-[100px]" />

      <aside className="fixed left-0 top-0 z-20 hidden h-screen w-72 flex-col border-r border-border bg-card backdrop-blur-3xl md:flex">
        <nav className="flex-1 space-y-2 px-4 py-20" aria-label="Dashboard navigation">
          <Link
            href="/dashboard"
            aria-current="page"
            className={`flex items-center gap-3 rounded-2xl border border-border bg-surface px-4 py-3 font-semibold text-foreground ${FOCUS_RING_CLASS}`}
          >
            <span>Dashboard</span>
          </Link>
          <Link
            href="/generator"
            className={`flex items-center gap-3 rounded-2xl px-4 py-3 font-semibold text-muted transition hover:bg-surface hover:text-foreground ${FOCUS_RING_CLASS}`}
          >
            <span>Link Generator</span>
          </Link>
          <Link
            href="/notifications"
            className={`flex items-center gap-3 rounded-2xl px-4 py-3 font-semibold text-muted transition hover:bg-surface hover:text-foreground ${FOCUS_RING_CLASS}`}
          >
            <span>Notifications</span>
          </Link>
          <Link
            href="/settings"
            className={`flex items-center gap-3 rounded-2xl px-4 py-3 font-semibold text-muted transition hover:bg-surface hover:text-foreground ${FOCUS_RING_CLASS}`}
          >
            <span>Profile Settings</span>
          </Link>
        </nav>
      </aside>

      <main id="dashboard-main" className="relative z-10 p-4 sm:p-6 md:ml-72 md:p-12">
        <header className="mb-10 flex flex-col gap-6 md:mb-16 md:flex-row md:items-start md:justify-between">
          <div>
            <nav className="mb-2 flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.24em] text-subtle md:mb-4">
              <span>QuickEx</span>
              <span>/</span>
              <span className="text-foreground">Dashboard</span>
            </nav>

            <h1 className="text-3xl font-semibold tracking-tight sm:text-4xl md:text-5xl">
              Welcome back.
            </h1>
            <p className="mt-2 text-sm font-medium text-muted sm:text-base md:text-lg">
              Your payments, escrows, and action items all in one place.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <Link
              href="/notifications"
              className={`rounded-xl border border-border-strong bg-surface px-4 py-3 text-sm font-semibold text-foreground transition hover:bg-surface-strong ${FOCUS_RING_CLASS}`}
              aria-label="Open notifications panel"
            >
              Open notifications
            </Link>
            <button
              type="button"
              onClick={() => setStatusMessage("Withdraw flow coming soon.")}
              className={`rounded-xl bg-indigo-500 px-4 py-3 font-semibold text-white shadow-lg transition hover:bg-indigo-400 ${FOCUS_RING_CLASS}`}
              aria-label="Withdraw funds"
            >
              Withdraw funds
            </button>
          </div>
        </header>

        <div className="mb-8 space-y-3">
          {spotlightMessage ? (
            <p className="rounded-2xl border border-indigo-400/20 bg-indigo-500/10 px-4 py-3 text-sm text-brand">
              {spotlightMessage}
            </p>
          ) : null}
          <p aria-live="polite" className="text-sm text-muted">
            {statusMessage ??
              "Notifications can jump you directly into payments, active bids, and listing updates."}
          </p>
        </div>

        <section className="mb-10 grid grid-cols-1 gap-6 sm:grid-cols-2 md:mb-16 lg:grid-cols-3">
          {metricsLoading ? (
            <>
              <div className="h-36 animate-pulse rounded-3xl border border-border bg-card p-6" />
              <div className="h-36 animate-pulse rounded-3xl border border-border bg-card p-6" />
              <div className="h-36 animate-pulse rounded-3xl border border-indigo-300/50 bg-indigo-500/50 p-6" />
            </>
          ) : metricsError ? (
            <div className="col-span-full rounded-3xl border border-red-500/20 bg-surface p-6 text-center">
              <p className="text-sm font-semibold text-danger">Failed to load backend metrics: {metricsError}</p>
              <button
                onClick={() => void loadMetrics()}
                className="mt-3 rounded-xl bg-indigo-500 px-4 py-2 text-xs font-bold text-white transition hover:bg-indigo-400"
              >
                Retry loading metrics
              </button>
            </div>
          ) : (
            <>
              {/* Card 1: Total Revenue / Volume */}
              <div className="group relative overflow-hidden rounded-3xl border border-border bg-card p-6 transition hover:border-indigo-500/30">
                <div className="absolute right-0 top-0 p-4 opacity-10 transition group-hover:opacity-20">
                  <span className="text-6xl font-semibold text-brand">$</span>
                </div>
                <p className="mb-1 text-xs font-semibold uppercase tracking-[0.24em] text-muted">
                  Total Volume
                </p>
                <div className="flex items-baseline gap-2">
                  <p className="text-4xl font-semibold text-foreground">
                    {formatCurrency(metricsData?.summary.totalVolume ?? 0)}
                  </p>
                  <span className="rounded-full bg-emerald-400/10 px-2 py-1 text-xs font-semibold text-success">
                    Live Backend Data
                  </span>
                </div>
                <p className="mt-2 text-xs text-subtle">
                  Avg tx size: {formatCurrency(metricsData?.summary.avgTxSize ?? 0)}
                </p>
              </div>

              {/* Card 2: Payment Count & Success Rate */}
              <div className="rounded-3xl border border-border bg-card p-6">
                <p className="mb-1 text-xs font-semibold uppercase tracking-[0.24em] text-muted">
                  Payments & Success Rate
                </p>
                <div className="flex items-baseline gap-2">
                  <p className="text-4xl font-semibold text-foreground">
                    {(metricsData?.summary.conversionRate ?? 100).toFixed(1)}%
                  </p>
                  <span className="text-sm font-medium text-muted">
                    ({metricsData?.summary.totalTx ?? 0} txs)
                  </span>
                </div>
                <div className="mt-3 h-1.5 w-full overflow-hidden rounded-full bg-surface-strong">
                  <div
                    className="h-full bg-indigo-400 transition-all duration-500"
                    style={{ width: `${Math.min(Math.max(metricsData?.summary.conversionRate ?? 100, 0), 100)}%` }}
                  />
                </div>
                <p className="mt-2 text-xs text-subtle">
                  {metricsData?.summary.successfulTx ?? 0} settled, {metricsData?.summary.failedTx ?? 0} failed
                </p>
              </div>

              {/* Card 3: Available Payout & Refunds */}
              <div className="rounded-3xl border border-indigo-300/50 bg-indigo-500 p-6 text-white shadow-[0_20px_40px_-15px_rgba(99,102,241,0.3)]">
                <p className="mb-1 text-xs font-semibold uppercase tracking-[0.24em] text-white/90">
                  Available Payout
                </p>
                <p className="text-4xl font-semibold text-white">
                  {formatCurrency((metricsData?.summary.totalVolume ?? 0) * 0.85).replace("$", "")}{" "}
                  <span className="text-xl opacity-80">USDC</span>
                </p>
                <p className="mt-3 text-xs text-white/90">
                  {metricsData?.summary.refundCount ?? 0} refunds • Estimated settlement: 3 seconds
                </p>
              </div>
            </>
          )}
        </section>

        <div className="mb-10 md:mb-16">
          <AnalyticsDashboard />
        </div>

        <section
          id="dashboard-activity"
          tabIndex={-1}
          className="overflow-hidden rounded-3xl border border-border bg-card shadow-2xl backdrop-blur-2xl"
        >
          <div className="flex flex-col justify-between gap-4 border-b border-border p-6 sm:flex-row sm:p-10">
            <div>
              <h2 className="text-2xl font-semibold text-foreground">Activity Feed</h2>
              <p className="mt-1 text-sm text-muted">
                Live payment history fetched from the Stellar network.
              </p>
            </div>

            <button
              type="button"
              onClick={handleRetry}
              disabled={loading}
              className={`rounded-xl border border-border bg-surface px-4 py-2 text-sm font-semibold text-muted transition hover:border-indigo-300/40 hover:text-foreground disabled:opacity-50 ${FOCUS_RING_CLASS}`}
              aria-label="Refresh activity feed"
            >
              {loading ? "Refreshing…" : "Refresh"}
            </button>
          </div>

          {data?.degraded ? (
            <div className="mx-6 mt-6 rounded-2xl border border-amber-300/30 bg-amber-400/5 p-4 sm:mx-10 sm:mt-10">
              <p className="text-sm font-medium text-amber-600 dark:text-amber-400">
                The activity feed is temporarily unavailable. Showing cached or
                partial data.{" "}
                <button
                  type="button"
                  onClick={handleRetry}
                  className="underline transition hover:text-amber-800 dark:hover:text-amber-300"
                >
                  Retry
                </button>
              </p>
            </div>
          ) : null}

          {!data || (data.items.length === 0 && !data.degraded) ? (
            <div className="flex flex-col items-center justify-center px-6 py-16 text-center sm:px-10">
              <div className="mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-surface">
                <svg
                  className="h-8 w-8 text-muted"
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                  strokeWidth={1.5}
                  aria-hidden="true"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    d="M12 6v6h4.5m4.5 0a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z"
                  />
                </svg>
              </div>
              <h3 className="text-lg font-semibold text-foreground">
                No activity yet
              </h3>
              <p className="mt-2 max-w-md text-sm text-muted">
                Your recent payments will appear here once transactions are
                detected on the Stellar network. Create a payment link to get
                started.
              </p>
              <Link
                href="/generator"
                className={`mt-6 rounded-xl bg-indigo-500 px-5 py-2.5 text-sm font-semibold text-white shadow-lg transition hover:bg-indigo-400 ${FOCUS_RING_CLASS}`}
              >
                Create payment link
              </Link>
            </div>
          ) : (
            <>
              <div className="border-b border-border bg-surface/60 p-6 sm:p-8">
                <PaymentHistoryFilters
                  allItems={data?.items ?? []}
                  filteredItems={filteredActivityItems}
                  filters={activityFilters}
                  onFiltersChange={setActivityFilters}
                  assetOptions={assetOptions}
                />
              </div>

              {filteredActivityItems.length === 0 ? (
                <div className="flex flex-col items-center justify-center px-6 py-16 text-center sm:px-10">
                  <div className="mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-surface">
                    <svg
                      className="h-8 w-8 text-muted"
                      fill="none"
                      viewBox="0 0 24 24"
                      stroke="currentColor"
                      strokeWidth={1.5}
                      aria-hidden="true"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        d="M21 21 16.65 16.65M11 7a4 4 0 1 1 0 8a4 4 0 0 1 0-8Z"
                      />
                    </svg>
                  </div>
                  <h3 className="text-lg font-semibold text-foreground">
                    No transactions match these filters
                  </h3>
                  <p className="mt-2 max-w-md text-sm text-muted">
                    Try a different keyword, status, or asset to find the payment you need.
                  </p>
                  <button
                    type="button"
                    onClick={clearActivityFilters}
                    className={`mt-6 rounded-xl bg-indigo-500 px-5 py-2.5 text-sm font-semibold text-white shadow-lg transition hover:bg-indigo-400 ${FOCUS_RING_CLASS}`}
                  >
                    Clear filters
                  </button>
                </div>
              ) : (
                <>
                  <div className="overflow-x-auto">
                    <table className="min-w-[700px] w-full text-left">
                      <caption className="sr-only">
                        Recent payment activity from the Stellar network.
                      </caption>
                      <thead>
                        <tr className="border-b border-border text-[10px] font-semibold uppercase tracking-[0.24em] text-muted">
                          <th className="px-6 py-4 sm:px-10 sm:py-6">Transaction</th>
                          <th className="px-6 py-4 sm:px-10 sm:py-6">Amount</th>
                          <th className="px-6 py-4 sm:px-10 sm:py-6">Memo / Status</th>
                          <th className="px-6 py-4 sm:px-10 sm:py-6">From / To</th>
                          <th className="px-6 py-4 sm:px-10 sm:py-6">Date</th>
                        </tr>
                      </thead>

                      <tbody className="divide-y divide-border">
                        {filteredActivityItems.map((item, index) => {
                          const isHighlighted =
                            item.id === highlightedTransaction;

                          return (
                            <tr
                              key={item.id}
                              id={toAnchorId("transaction", item.id)}
                              tabIndex={-1}
                              className={`transition ${
                                isHighlighted
                                  ? "bg-indigo-500/10"
                                  : "hover:bg-surface"
                              }`}
                            >
                              <td className="px-6 py-6 sm:px-10">
                                <div className="flex items-center gap-3">
                                  <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-surface font-mono text-[10px] opacity-70">
                                    #{index + 1}
                                  </span>
                                  <span className="font-mono text-sm text-foreground sm:text-base">
                                    {shortAddress(item.id)}
                                  </span>
                                </div>
                              </td>
                              <td className="px-6 py-6 text-lg font-semibold sm:px-10">
                                {item.amount} {item.asset}
                              </td>
                              <td className="px-6 py-6 sm:px-10">
                                <div className="flex flex-col gap-1.5">
                                  {item.memo ? (
                                    <span className="font-semibold text-foreground">
                                      {item.memo}
                                    </span>
                                  ) : (
                                    <span className="text-xs italic text-subtle">
                                      No memo
                                    </span>
                                  )}
                                  <span
                                    className={`inline-flex w-fit items-center rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.24em] ${getStatusClasses(
                                      item.status,
                                    )}`}
                                  >
                                    {item.status}
                                  </span>
                                </div>
                              </td>
                              <td className="px-6 py-6 sm:px-10">
                                <div className="flex flex-col gap-1">
                                  <span className="text-xs text-muted">
                                    From:{" "}
                                    <span className="font-mono text-subtle">
                                      {shortAddress(item.source)}
                                    </span>
                                  </span>
                                  <span className="text-xs text-muted">
                                    To:{" "}
                                    <span className="font-mono text-subtle">
                                      {shortAddress(item.destination)}
                                    </span>
                                  </span>
                                </div>
                              </td>
                              <td className="px-6 py-6 text-muted sm:px-10">
                                {item.date}
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>

                  <div className="bg-surface p-6 text-center sm:p-8">
                    <Link
                      href="/notifications?category=payments"
                      className={`text-sm font-semibold text-muted transition hover:text-foreground ${FOCUS_RING_CLASS}`}
                    >
                      View payment alerts
                    </Link>
                  </div>
                </>
              )}
            </>
          )}
        </section>

        <section className="mt-10 overflow-hidden rounded-3xl border border-border bg-card shadow-2xl backdrop-blur-2xl md:mt-16">
          <div className="flex flex-col items-start justify-between gap-4 border-b border-border p-6 sm:flex-row sm:items-center sm:p-10">
            <div>
              <h2 className="text-2xl font-semibold text-foreground">
                Escrow and Listing Activity
              </h2>
              <p className="mt-1 text-sm text-muted">
                Notifications here land on the exact bid or listing that needs
                your attention.
              </p>
            </div>
            <Link
              href="/notifications?category=escrows"
              className={`rounded-xl border border-indigo-300/40 bg-indigo-500/10 px-5 py-2.5 text-sm font-semibold text-brand transition hover:bg-indigo-500 hover:text-white ${FOCUS_RING_CLASS}`}
            >
              Open escrow alerts
            </Link>
          </div>

          <div className="grid divide-y divide-border md:grid-cols-2 md:divide-x md:divide-y-0">
            <div id="dashboard-bids" tabIndex={-1} className="p-6 sm:p-8">
              <h3 className="mb-5 text-sm font-semibold uppercase tracking-[0.24em] text-muted">
                My Active Bids
              </h3>
              {userBids.length === 0 ? (
                <p className="text-sm text-muted">No active bids yet.</p>
              ) : (
                <div className="space-y-3">
                  {userBids.map((bid) => (
                    <div
                      key={bid.username}
                      id={toAnchorId("bid", bid.username)}
                      tabIndex={-1}
                      className={`flex items-center justify-between rounded-2xl border p-4 ${
                        bid.username === highlightedBid
                          ? "border-indigo-300/40 bg-indigo-500/10"
                          : "border-border bg-surface"
                      }`}
                    >
                      <div>
                        <p className="text-base font-semibold text-foreground">
                          @{bid.username}
                        </p>
                        <p className="text-[11px] text-muted">
                          My bid: {bid.myBid} USDC. Current: {bid.currentBid} USDC. Ends{" "}
                          {formatCountdown(bid.endsAt)}
                        </p>
                      </div>
                      <span
                        className={`rounded-full px-2 py-1 text-[10px] font-semibold uppercase tracking-[0.24em] ${
                          bid.isWinning
                            ? "border border-emerald-300/40 bg-emerald-400/10 text-success"
                            : "border border-danger-soft/40 bg-red-400/10 text-danger"
                        }`}
                      >
                        {bid.isWinning ? "Winning" : "Outbid"}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div id="dashboard-listings" tabIndex={-1} className="p-6 sm:p-8">
              <h3 className="mb-5 text-sm font-semibold uppercase tracking-[0.24em] text-muted">
                My Listings
              </h3>
              {userListings.length === 0 ? (
                <p className="text-sm text-muted">
                  No usernames listed yet.
                </p>
              ) : (
                <div className="space-y-3">
                  {userListings.map((listing) => (
                    <div
                      key={listing.username}
                      id={toAnchorId("listing", listing.username)}
                      tabIndex={-1}
                      className={`rounded-2xl border p-4 ${
                        listing.username === highlightedListing
                          ? "border-indigo-300/40 bg-indigo-500/10"
                          : "border-border bg-surface"
                      }`}
                    >
                      <div className="mb-2 flex items-start justify-between">
                        <p className="text-base font-semibold text-foreground">
                          @{listing.username}
                        </p>
                        <span className="rounded-full border border-indigo-300/40 bg-indigo-400/10 px-2 py-1 text-[10px] font-semibold text-brand">
                          {listing.bidCount} bids
                        </span>
                      </div>
                      <div className="flex justify-between text-[11px] text-muted">
                        <span>Current: {listing.currentBid} USDC</span>
                        <span>Ends: {formatCountdown(listing.endsAt)}</span>
                      </div>
                      <div className="mt-2 h-1 w-full overflow-hidden rounded-full bg-surface">
                        <div
                          className="h-full rounded-full bg-indigo-400"
                          style={{
                            width: `${Math.min(
                              100,
                              (listing.currentBid / (listing.minBid * 5)) * 100,
                            )}%`,
                          }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </section>
      </main>
    </div>
  );
}

export default function Dashboard() {
  return (
    <Suspense
      fallback={<p className="text-muted">Loading dashboard...</p>}
    >
      <DashboardContent />
    </Suspense>
  );
}
