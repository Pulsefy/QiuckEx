"use client";

import { Suspense, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import AnalyticsDashboard from "@/components/AnalyticsDashboard";
import { NetworkBadge } from "@/components/NetworkBadge";
import { useApi } from "@/hooks/useApi";
import {
  fetchUserBids,
  fetchUserListings,
  formatCountdown,
  type UserBid,
  type UserListing,
} from "@/hooks/marketplaceApi";
import { mockContractCall, mockFetch } from "@/hooks/mockApi";

type ActivityItem = {
  id: string;
  amount: string;
  asset: string;
  memo: string;
  date: string;
  status: "Pending" | "Settled" | "Privacy Enabled";
  privacy: "Enabled" | "Public";
  action: "extend" | "cleanup";
};

type DashboardResponse = {
  items: ActivityItem[];
};

const ACTIVITY_ITEMS: ActivityItem[] = [
  {
    id: "GD2P...5H2W",
    amount: "50.00",
    asset: "USDC",
    memo: "Project milestone #1",
    date: "2 mins ago",
    status: "Pending",
    privacy: "Enabled",
    action: "extend",
  },
  {
    id: "GD1R...3K9L",
    amount: "125.00",
    asset: "XLM",
    memo: "Frontend consulting",
    date: "Jan 20, 14:32",
    status: "Settled",
    privacy: "Public",
    action: "cleanup",
  },
  {
    id: "GC8T...9Q0M",
    amount: "20.00",
    asset: "USDC",
    memo: "Subscription renewal",
    date: "Jan 19, 09:12",
    status: "Privacy Enabled",
    privacy: "Enabled",
    action: "cleanup",
  },
];

function toAnchorId(prefix: string, value: string) {
  return `${prefix}-${value.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`;
}

function getStatusClasses(status: ActivityItem["status"]) {
  switch (status) {
    case "Pending":
      return "text-warning";
    case "Settled":
      return "text-success";
    default:
      return "text-brand";
  }
}

const FOCUS_RING_CLASS =
  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300 focus-visible:ring-offset-2 focus-visible:ring-offset-background";

function DashboardContent() {
  const searchParams = useSearchParams();
  const { data, error, loading, callApi } = useApi<DashboardResponse>();
  const [userBids, setUserBids] = useState<UserBid[]>([]);
  const [userListings, setUserListings] = useState<UserListing[]>([]);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);

  useEffect(() => {
    void callApi(() =>
      mockFetch({
        items: ACTIVITY_ITEMS,
      }),
    );
    void fetchUserBids().then(setUserBids);
    void fetchUserListings().then(setUserListings);
  }, [callApi]);

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

  const handleExtend = async (id: string) => {
    await mockContractCall("extend", id);
    setStatusMessage(`Storage TTL extended for transaction ${id}.`);
  };

  const handleCleanup = async (id: string) => {
    await mockContractCall("cleanup", id);
    setStatusMessage(`Storage deposit reclaimed for transaction ${id}.`);
  };

  if (loading) {
    return <p className="text-muted">Loading dashboard...</p>;
  }

  if (error) {
    return <p className="text-danger">{error}</p>;
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
          <div className="group relative overflow-hidden rounded-3xl border border-border bg-card p-6 transition hover:border-indigo-500/30">
            <div className="absolute right-0 top-0 p-4 opacity-10 transition group-hover:opacity-20">
              <span className="text-6xl font-semibold text-brand">$</span>
            </div>
            <p className="mb-1 text-xs font-semibold uppercase tracking-[0.24em] text-muted">
              Total Revenue
            </p>
            <div className="flex items-baseline gap-2">
              <p className="text-4xl font-semibold text-foreground">$1,240.50</p>
              <span className="rounded-full bg-emerald-400/10 px-2 py-1 text-xs font-semibold text-success">
                +12.5%
              </span>
            </div>
          </div>

          <div className="rounded-3xl border border-border bg-card p-6">
            <p className="mb-1 text-xs font-semibold uppercase tracking-[0.24em] text-muted">
              Success Rate
            </p>
            <p className="text-4xl font-semibold text-foreground">98.2%</p>
            <div className="mt-3 h-1.5 w-full overflow-hidden rounded-full bg-surface-strong">
              <div className="h-full w-[98%] bg-indigo-400" />
            </div>
          </div>

          <div className="rounded-3xl border border-indigo-300/50 bg-indigo-500 p-6 text-white shadow-[0_20px_40px_-15px_rgba(99,102,241,0.3)]">
            <p className="mb-1 text-xs font-semibold uppercase tracking-[0.24em] text-white/90">
              Available Payout
            </p>
            <p className="text-4xl font-semibold text-white">
              850.00 <span className="text-xl opacity-80">USDC</span>
            </p>
            <p className="mt-3 text-xs text-white/90">
              Estimated settlement: 3 seconds
            </p>
          </div>
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
                Direct payment history, with actions and notification deep links.
              </p>
            </div>

            <div className="rounded-xl border border-border bg-surface p-2">
              <label htmlFor="dashboard-range" className="sr-only">
                Filter activity period
              </label>
              <select
                id="dashboard-range"
                className={`bg-transparent text-sm font-semibold text-foreground ${FOCUS_RING_CLASS}`}
                defaultValue="Last 30 Days"
              >
                <option>Last 30 Days</option>
                <option>Yearly</option>
              </select>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="min-w-[700px] w-full text-left">
              <caption className="sr-only">
                Recent payment activity with actions to extend TTL or clean up
                completed records.
              </caption>
              <thead>
                <tr className="border-b border-border text-[10px] font-semibold uppercase tracking-[0.24em] text-muted">
                  <th className="px-6 py-4 sm:px-10 sm:py-6">Transaction ID</th>
                  <th className="px-6 py-4 sm:px-10 sm:py-6">Asset</th>
                  <th className="px-6 py-4 sm:px-10 sm:py-6">Memo / Status</th>
                  <th className="px-6 py-4 sm:px-10 sm:py-6">Timestamp</th>
                  <th className="px-6 py-4 text-right sm:px-10 sm:py-6">
                    Actions
                  </th>
                </tr>
              </thead>

              <tbody className="divide-y divide-border">
                {(data?.items ?? []).map((item, index) => {
                  const isHighlighted = item.id === highlightedTransaction;

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
                            {item.id}
                          </span>
                        </div>
                      </td>
                      <td className="px-6 py-6 text-lg font-semibold sm:px-10">
                        {item.amount} {item.asset}
                      </td>
                      <td className="px-6 py-6 sm:px-10">
                        <div className="flex flex-col">
                          <span className="font-semibold text-foreground">
                            {item.memo}
                          </span>
                          <div className="mt-1 flex items-center gap-2">
                            <span
                              className={`text-[10px] font-semibold uppercase tracking-[0.24em] ${getStatusClasses(
                                item.status,
                              )}`}
                            >
                              {item.status}
                            </span>
                            <span className="text-[10px] font-semibold uppercase tracking-[0.24em] text-muted">
                              Privacy {item.privacy}
                            </span>
                          </div>
                        </div>
                      </td>
                      <td className="px-6 py-6 text-muted sm:px-10">
                        {item.date}
                      </td>
                      <td className="px-6 py-6 text-right sm:px-10">
                        {item.action === "extend" ? (
                          <button
                            type="button"
                            onClick={() => void handleExtend(item.id)}
                            className={`rounded-full bg-indigo-500/10 px-3 py-1.5 text-[10px] font-semibold uppercase tracking-[0.24em] text-brand transition hover:bg-indigo-500 hover:text-white ${FOCUS_RING_CLASS}`}
                            aria-label={`Extend TTL for transaction ${item.id}`}
                          >
                            Extend TTL
                          </button>
                        ) : (
                          <button
                            type="button"
                            onClick={() => void handleCleanup(item.id)}
                            className={`rounded-full bg-red-500/10 px-3 py-1.5 text-[10px] font-semibold uppercase tracking-[0.24em] text-danger transition hover:bg-red-500 hover:text-white ${FOCUS_RING_CLASS}`}
                            aria-label={`Clean up transaction ${item.id}`}
                          >
                            Cleanup
                          </button>
                        )}
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
                          My bid: {bid.myBid} USDC. Ends{" "}
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
