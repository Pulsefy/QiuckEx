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
      return "text-amber-300";
    case "Settled":
      return "text-emerald-300";
    default:
      return "text-indigo-200";
  }
}

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
      document.getElementById(focusTargetId)?.scrollIntoView({
        behavior: "smooth",
        block: "center",
      });
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
    return <p className="text-neutral-200">Loading dashboard...</p>;
  }

  if (error) {
    return <p className="text-red-300">{error}</p>;
  }

  return (
    <div className="relative min-h-screen text-white">
      <NetworkBadge />

      <div className="fixed left-[-30%] top-[-20%] h-[60%] w-[60%] rounded-full bg-indigo-500/10 blur-[120px]" />
      <div className="fixed bottom-[-20%] right-[-30%] h-[50%] w-[50%] rounded-full bg-purple-500/5 blur-[100px]" />

      <aside className="fixed left-0 top-0 z-20 hidden h-screen w-72 flex-col border-r border-white/5 bg-black/20 backdrop-blur-3xl md:flex">
        <nav className="flex-1 space-y-2 px-4 py-20">
          <Link
            href="/dashboard"
            aria-current="page"
            className="flex items-center gap-3 rounded-2xl border border-white/5 bg-white/5 px-4 py-3 font-semibold text-white"
          >
            <span>Dashboard</span>
          </Link>
          <Link
            href="/generator"
            className="flex items-center gap-3 rounded-2xl px-4 py-3 font-semibold text-neutral-200 transition hover:bg-white/5 hover:text-white"
          >
            <span>Link Generator</span>
          </Link>
          <Link
            href="/notifications"
            className="flex items-center gap-3 rounded-2xl px-4 py-3 font-semibold text-neutral-200 transition hover:bg-white/5 hover:text-white"
          >
            <span>Notifications</span>
          </Link>
          <Link
            href="/settings"
            className="flex items-center gap-3 rounded-2xl px-4 py-3 font-semibold text-neutral-200 transition hover:bg-white/5 hover:text-white"
          >
            <span>Profile Settings</span>
          </Link>
        </nav>
      </aside>

      <main className="relative z-10 p-4 sm:p-6 md:ml-72 md:p-12">
        <header className="mb-10 flex flex-col gap-6 md:mb-16 md:flex-row md:items-start md:justify-between">
          <div>
            <nav className="mb-2 flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.24em] text-neutral-400 md:mb-4">
              <span>QuickEx</span>
              <span>/</span>
              <span className="text-neutral-100">Dashboard</span>
            </nav>

            <h1 className="text-3xl font-semibold tracking-tight sm:text-4xl md:text-5xl">
              Welcome back.
            </h1>
            <p className="mt-2 text-sm font-medium text-neutral-200 sm:text-base md:text-lg">
              Your payments, escrows, and action items all in one place.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <Link
              href="/notifications"
              className="rounded-xl border border-white/10 bg-white/5 px-4 py-3 text-sm font-semibold text-neutral-100 transition hover:bg-white/10"
            >
              Open notifications
            </Link>
            <button
              type="button"
              onClick={() => setStatusMessage("Withdraw flow coming soon.")}
              className="rounded-xl bg-indigo-500 px-4 py-3 font-semibold text-white shadow-lg transition hover:bg-indigo-400"
            >
              Withdraw funds
            </button>
          </div>
        </header>

        <div className="mb-8 space-y-3">
          {spotlightMessage ? (
            <p className="rounded-2xl border border-indigo-400/20 bg-indigo-500/10 px-4 py-3 text-sm text-indigo-50">
              {spotlightMessage}
            </p>
          ) : null}
          <p aria-live="polite" className="text-sm text-neutral-200">
            {statusMessage ??
              "Notifications can jump you directly into payments, active bids, and listing updates."}
          </p>
        </div>

        <section className="mb-10 grid grid-cols-1 gap-6 sm:grid-cols-2 md:mb-16 lg:grid-cols-3">
          <div className="group relative overflow-hidden rounded-3xl border border-white/5 bg-neutral-900/40 p-6 transition hover:border-indigo-500/30">
            <div className="absolute right-0 top-0 p-4 opacity-10 transition group-hover:opacity-20">
              <span className="text-6xl font-semibold text-indigo-300">$</span>
            </div>
            <p className="mb-1 text-xs font-semibold uppercase tracking-[0.24em] text-neutral-300">
              Total Revenue
            </p>
            <div className="flex items-baseline gap-2">
              <p className="text-4xl font-semibold text-white">$1,240.50</p>
              <span className="rounded-full bg-emerald-400/10 px-2 py-1 text-xs font-semibold text-emerald-200">
                +12.5%
              </span>
            </div>
          </div>

          <div className="rounded-3xl border border-white/5 bg-neutral-900/40 p-6">
            <p className="mb-1 text-xs font-semibold uppercase tracking-[0.24em] text-neutral-300">
              Success Rate
            </p>
            <p className="text-4xl font-semibold text-white">98.2%</p>
            <div className="mt-3 h-1.5 w-full overflow-hidden rounded-full bg-neutral-800">
              <div className="h-full w-[98%] bg-indigo-400" />
            </div>
          </div>

          <div className="rounded-3xl border border-indigo-300/50 bg-indigo-500 p-6 shadow-[0_20px_40px_-15px_rgba(99,102,241,0.3)]">
            <p className="mb-1 text-xs font-semibold uppercase tracking-[0.24em] text-indigo-50/90">
              Available Payout
            </p>
            <p className="text-4xl font-semibold text-white">
              850.00 <span className="text-xl opacity-80">USDC</span>
            </p>
            <p className="mt-3 text-xs text-indigo-50/90">
              Estimated settlement: 3 seconds
            </p>
          </div>
        </section>

        <div className="mb-10 md:mb-16">
          <AnalyticsDashboard />
        </div>

        <section
          id="dashboard-activity"
          className="overflow-hidden rounded-3xl border border-white/5 bg-black/40 shadow-2xl backdrop-blur-2xl"
        >
          <div className="flex flex-col justify-between gap-4 border-b border-white/5 p-6 sm:flex-row sm:p-10">
            <div>
              <h2 className="text-2xl font-semibold text-white">Activity Feed</h2>
              <p className="mt-1 text-sm text-neutral-200">
                Direct payment history, with actions and notification deep links.
              </p>
            </div>

            <div className="rounded-xl border border-white/5 bg-white/5 p-2">
              <label htmlFor="dashboard-range" className="sr-only">
                Filter activity period
              </label>
              <select
                id="dashboard-range"
                className="bg-transparent text-sm font-semibold text-neutral-100"
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
                <tr className="border-b border-white/5 text-[10px] font-semibold uppercase tracking-[0.24em] text-neutral-300">
                  <th className="px-6 py-4 sm:px-10 sm:py-6">Transaction ID</th>
                  <th className="px-6 py-4 sm:px-10 sm:py-6">Asset</th>
                  <th className="px-6 py-4 sm:px-10 sm:py-6">Memo / Status</th>
                  <th className="px-6 py-4 sm:px-10 sm:py-6">Timestamp</th>
                  <th className="px-6 py-4 text-right sm:px-10 sm:py-6">
                    Actions
                  </th>
                </tr>
              </thead>

              <tbody className="divide-y divide-white/5">
                {(data?.items ?? []).map((item, index) => {
                  const isHighlighted = item.id === highlightedTransaction;

                  return (
                    <tr
                      key={item.id}
                      id={toAnchorId("transaction", item.id)}
                      className={`transition ${
                        isHighlighted
                          ? "bg-indigo-500/10"
                          : "hover:bg-white/[0.03]"
                      }`}
                    >
                      <td className="px-6 py-6 sm:px-10">
                        <div className="flex items-center gap-3">
                          <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-white/5 font-mono text-[10px] opacity-70">
                            #{index + 1}
                          </span>
                          <span className="font-mono text-sm text-neutral-100 sm:text-base">
                            {item.id}
                          </span>
                        </div>
                      </td>
                      <td className="px-6 py-6 text-lg font-semibold sm:px-10">
                        {item.amount} {item.asset}
                      </td>
                      <td className="px-6 py-6 sm:px-10">
                        <div className="flex flex-col">
                          <span className="font-semibold text-neutral-100">
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
                            <span className="text-[10px] font-semibold uppercase tracking-[0.24em] text-neutral-300">
                              Privacy {item.privacy}
                            </span>
                          </div>
                        </div>
                      </td>
                      <td className="px-6 py-6 text-neutral-200 sm:px-10">
                        {item.date}
                      </td>
                      <td className="px-6 py-6 text-right sm:px-10">
                        {item.action === "extend" ? (
                          <button
                            type="button"
                            onClick={() => void handleExtend(item.id)}
                            className="rounded-full bg-indigo-500/10 px-3 py-1.5 text-[10px] font-semibold uppercase tracking-[0.24em] text-indigo-100 transition hover:bg-indigo-500 hover:text-white"
                          >
                            Extend TTL
                          </button>
                        ) : (
                          <button
                            type="button"
                            onClick={() => void handleCleanup(item.id)}
                            className="rounded-full bg-red-500/10 px-3 py-1.5 text-[10px] font-semibold uppercase tracking-[0.24em] text-red-100 transition hover:bg-red-500 hover:text-white"
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

          <div className="bg-white/[0.01] p-6 text-center sm:p-8">
            <Link
              href="/notifications?category=payments"
              className="text-sm font-semibold text-neutral-200 transition hover:text-white"
            >
              View payment alerts
            </Link>
          </div>
        </section>

        <section className="mt-10 overflow-hidden rounded-3xl border border-white/5 bg-black/40 shadow-2xl backdrop-blur-2xl md:mt-16">
          <div className="flex flex-col items-start justify-between gap-4 border-b border-white/5 p-6 sm:flex-row sm:items-center sm:p-10">
            <div>
              <h2 className="text-2xl font-semibold text-white">
                Escrow and Listing Activity
              </h2>
              <p className="mt-1 text-sm text-neutral-200">
                Notifications here land on the exact bid or listing that needs
                your attention.
              </p>
            </div>
            <Link
              href="/notifications?category=escrows"
              className="rounded-xl border border-indigo-300/40 bg-indigo-500/10 px-5 py-2.5 text-sm font-semibold text-indigo-100 transition hover:bg-indigo-500 hover:text-white"
            >
              Open escrow alerts
            </Link>
          </div>

          <div className="grid divide-y divide-white/5 md:grid-cols-2 md:divide-x md:divide-y-0">
            <div id="dashboard-bids" className="p-6 sm:p-8">
              <h3 className="mb-5 text-sm font-semibold uppercase tracking-[0.24em] text-neutral-300">
                My Active Bids
              </h3>
              {userBids.length === 0 ? (
                <p className="text-sm text-neutral-200">No active bids yet.</p>
              ) : (
                <div className="space-y-3">
                  {userBids.map((bid) => (
                    <div
                      key={bid.username}
                      id={toAnchorId("bid", bid.username)}
                      className={`flex items-center justify-between rounded-2xl border p-4 ${
                        bid.username === highlightedBid
                          ? "border-indigo-300/40 bg-indigo-500/10"
                          : "border-white/5 bg-white/[0.03]"
                      }`}
                    >
                      <div>
                        <p className="text-base font-semibold text-white">
                          @{bid.username}
                        </p>
                        <p className="text-[11px] text-neutral-200">
                          My bid: {bid.myBid} USDC. Ends{" "}
                          {formatCountdown(bid.endsAt)}
                        </p>
                      </div>
                      <span
                        className={`rounded-full px-2 py-1 text-[10px] font-semibold uppercase tracking-[0.24em] ${
                          bid.isWinning
                            ? "border border-emerald-300/40 bg-emerald-400/10 text-emerald-200"
                            : "border border-red-300/40 bg-red-400/10 text-red-200"
                        }`}
                      >
                        {bid.isWinning ? "Winning" : "Outbid"}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div id="dashboard-listings" className="p-6 sm:p-8">
              <h3 className="mb-5 text-sm font-semibold uppercase tracking-[0.24em] text-neutral-300">
                My Listings
              </h3>
              {userListings.length === 0 ? (
                <p className="text-sm text-neutral-200">
                  No usernames listed yet.
                </p>
              ) : (
                <div className="space-y-3">
                  {userListings.map((listing) => (
                    <div
                      key={listing.username}
                      id={toAnchorId("listing", listing.username)}
                      className={`rounded-2xl border p-4 ${
                        listing.username === highlightedListing
                          ? "border-indigo-300/40 bg-indigo-500/10"
                          : "border-white/5 bg-white/[0.03]"
                      }`}
                    >
                      <div className="mb-2 flex items-start justify-between">
                        <p className="text-base font-semibold text-white">
                          @{listing.username}
                        </p>
                        <span className="rounded-full border border-indigo-300/40 bg-indigo-400/10 px-2 py-1 text-[10px] font-semibold text-indigo-100">
                          {listing.bidCount} bids
                        </span>
                      </div>
                      <div className="flex justify-between text-[11px] text-neutral-200">
                        <span>Current: {listing.currentBid} USDC</span>
                        <span>Ends: {formatCountdown(listing.endsAt)}</span>
                      </div>
                      <div className="mt-2 h-1 w-full overflow-hidden rounded-full bg-white/5">
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
      fallback={<p className="text-neutral-200">Loading dashboard...</p>}
    >
      <DashboardContent />
    </Suspense>
  );
}
