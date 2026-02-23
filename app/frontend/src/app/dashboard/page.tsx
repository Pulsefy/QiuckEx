"use client";

import Link from "next/link";
import { NetworkBadge } from "@/components/NetworkBadge";
import { useApi } from "@/hooks/useApi";
import { mockFetch } from "@/hooks/mockApi";
import { useEffect } from "react";

type DashboardResponse = {
  items: Array<Record<string, unknown>>;
};

export default function Dashboard() {
  const { data, error, loading, callApi } = useApi<DashboardResponse>();

  useEffect(() => {
    callApi(() =>
      mockFetch({
        items: [],
      })
    );
  }, []);

  if (loading) return <p>Loading dashboard...</p>;
  if (error) return <p>{error}</p>;
   if (!data || !data.items || data.items.length === 0) {
    return <p>No transactions yet. Create your first payment link!</p>;
  }


  return (
    <div className="relative min-h-screen text-white selection:bg-indigo-500/30">
      <NetworkBadge />

      {/* Background glows */}
      <div className="fixed top-[-20%] left-[-30%] w-[60%] h-[60%] bg-indigo-500/10 blur-[120px] rounded-full" />
      <div className="fixed bottom-[-20%] right-[-30%] w-[50%] h-[50%] bg-purple-500/5 blur-[100px] rounded-full" />

     

      {/* DESKTOP SIDEBAR */}
      <aside className="hidden md:flex w-72 h-screen fixed left-0 top-0 border-r border-white/5 bg-black/20 backdrop-blur-3xl flex-col z-20">
        
        
        <nav className="flex-1 px-4 py-30 space-y-2 ">
          <Link href="/dashboard" className="flex items-center gap-3 px-4 py-3 bg-white/5 border border-white/5 rounded-2xl font-bold">
            <span className="text-indigo-400">📊</span> Dashboard
          </Link>
          <Link href="/generator" className="flex items-center gap-3 px-4 py-3 text-neutral-500 hover:text-white hover:bg-white/5 rounded-2xl font-semibold">
            <span>⚡</span> Link Generator
          </Link>
        </nav>
      </aside>

      {/* MAIN CONTENT */}
      <main className="relative z-10 p-4 sm:p-6 md:p-12 md:ml-72">
        
        {/* HEADER */}
        <header className="mb-10 md:mb-16 flex flex-col md:flex-row md:justify-between md:items-start gap-6">
          <div>
            <nav className="flex items-center gap-2 text-xs font-bold text-neutral-600 uppercase tracking-widest mb-2 md:mb-4">
              <span>QuickEx</span> / <span className="text-neutral-400">Overview</span>
            </nav>

            <h1 className="text-3xl sm:text-4xl md:text-5xl font-black tracking-tight mb-2">
              Welcome back.
            </h1>
            <p className="text-neutral-500 font-medium text-sm sm:text-base md:text-lg">
              Your global payments are scaling beautifully.
            </p>
          </div>

          <button className="px-4 sm:px-6 py-3 bg-indigo-500 text-white font-bold rounded-xl shadow-lg hover:scale-105 active:scale-95 transition">
            Withdraw Funds
          </button>
        </header>

        {/* CARDS GRID */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6 md:gap-8 mb-10 md:mb-16">
          {/* Revenue card */}
          <div className="relative group overflow-hidden p-6 sm:p-8 rounded-3xl bg-neutral-900/40 border border-white/5 hover:border-indigo-500/30 transition">
            <div className="absolute top-0 right-0 p-4 opacity-10 group-hover:opacity-20">
              <span className="text-5xl sm:text-6xl text-indigo-500 font-black">$</span>
            </div>
            <p className="text-xs sm:text-sm text-neutral-500 mb-1 font-bold uppercase">Total Revenue</p>
            <div className="flex items-baseline gap-2">
              <p className="text-3xl sm:text-5xl font-black">$1,240.50</p>
              <span className="text-xs font-black text-green-500 bg-green-500/10 px-2 py-1 rounded-lg">+12.5%</span>
            </div>
          </div>

          {/* Success rate */}
          <div className="p-6 sm:p-8 rounded-3xl bg-neutral-900/40 border border-white/5">
            <p className="text-xs sm:text-sm text-neutral-500 mb-1 font-bold uppercase">Success Rate</p>
            <p className="text-3xl sm:text-5xl font-black">98.2%</p>
            <div className="mt-3 w-full h-1.5 bg-neutral-800 rounded-full overflow-hidden">
              <div className="w-[98%] h-full bg-indigo-500" />
            </div>
          </div>

          {/* Payout */}
          <div className="p-6 sm:p-8 rounded-3xl bg-indigo-500 border border-indigo-400 shadow-[0_20px_40px_-15px_rgba(99,102,241,0.3)]">
            <p className="text-xs sm:text-sm text-indigo-100/60 mb-1 font-bold uppercase">Available Payout</p>
            <p className="text-3xl sm:text-5xl font-black">
              850.00 <span className="text-base sm:text-2xl opacity-60">USDC</span>
            </p>
            <p className="text-[10px] sm:text-xs text-indigo-100/40 mt-3 italic">
              Estimated settlement: 3 seconds
            </p>
          </div>
        </div>

        {/* TABLE */}
        <div className="rounded-3xl bg-black/40 border border-white/5 backdrop-blur-2xl shadow-2xl overflow-hidden">
          <div className="p-6 sm:p-10 border-b border-white/5 flex flex-col sm:flex-row justify-between gap-4">
            <div>
              <h2 className="text-xl sm:text-2xl font-black mb-1">Activity Feed</h2>
              <p className="text-xs sm:text-sm text-neutral-500">Synced with Stellar Horizon API</p>
            </div>

            <div className="bg-white/5 p-2 rounded-xl border border-white/5">
              <select className="bg-transparent text-sm font-bold text-neutral-400 focus:outline-none">
                <option>Last 30 Days</option>
                <option>Yearly</option>
              </select>
            </div>
          </div>

          {/* Scrollable table */}
          <div className="overflow-x-auto">
            <table className="w-full text-left min-w-[600px]">
              <thead>
                <tr className="text-[9px] sm:text-[10px] font-black text-neutral-600 uppercase tracking-widest border-b border-white/5">
                  <th className="px-6 sm:px-10 py-4 sm:py-6">Transaction ID</th>
                  <th className="px-6 sm:px-10 py-4 sm:py-6">Asset</th>
                  <th className="px-6 sm:px-10 py-4 sm:py-6">Memo</th>
                  <th className="px-6 sm:px-10 py-4 sm:py-6 text-right">Timestamp</th>
                </tr>
              </thead>

              <tbody className="divide-y divide-white/5">
                {[
                  { id: "GD2P...5H2W", amount: "50.00 USDC", memo: "Project Milestone #1", date: "2 mins ago", status: "Privacy Enabled" },
                  { id: "GD1R...3K9L", amount: "125.00 XLM", memo: "Frontend Consulting", date: "Jan 20, 14:32", status: "Public" },
                  { id: "GC8T...9Q0M", amount: "20.00 USDC", memo: "Subscription Renewal", date: "Jan 19, 09:12", status: "Privacy Enabled" },
                ].map((tx, i) => (
                  <tr key={i} className="hover:bg-white/[0.03] transition">
                    <td className="px-6 sm:px-10 py-6">
                      <div className="flex items-center gap-3">
                        <span className="w-6 h-6 sm:w-8 sm:h-8 rounded-lg bg-white/5 flex items-center justify-center text-[10px] opacity-50 font-mono">
                          #{i + 1}
                        </span>
                        <span className="font-mono text-neutral-400 text-sm sm:text-base">{tx.id}</span>
                      </div>
                    </td>
                    <td className="px-6 sm:px-10 py-6 font-black text-lg">{tx.amount}</td>
                    <td className="px-6 sm:px-10 py-6">
                      <div className="flex flex-col">
                        <span className="text-neutral-300 font-bold">{tx.memo}</span>
                        <span className={`text-[9px] uppercase font-black tracking-widest mt-1 ${
                          tx.status.includes("Privacy") ? "text-indigo-400" : "text-neutral-600"
                        }`}>
                          {tx.status}
                        </span>
                      </div>
                    </td>
                    <td className="px-6 sm:px-10 py-6 text-neutral-500 text-right">{tx.date}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="p-6 sm:p-8 bg-white/[0.01] text-center">
            <button className="text-xs sm:text-sm font-black text-neutral-500 hover:text-white tracking-widest uppercase transition">
              View Full Ledger →
            </button>
          </div>
        </div>

      </main>
    </div>
  );
}
