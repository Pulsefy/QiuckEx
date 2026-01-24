import Link from "next/link";
import { NetworkBadge } from "@/components/NetworkBadge";

export default function Dashboard() {
  return (
    <div className="min-h-screen bg-neutral-950 text-white selection:bg-indigo-500/30 overflow-x-hidden">
      <NetworkBadge />
      
      <div className="flex min-h-screen relative">
        <div className="fixed top-[-10%] left-[-10%] w-[40%] h-[40%] bg-indigo-500/10 blur-[120px] rounded-full" />
        <div className="fixed bottom-[-10%] right-[-10%] w-[30%] h-[30%] bg-purple-500/5 blur-[100px] rounded-full" />

        <aside className="w-72 h-screen border-r border-white/5 bg-black/20 backdrop-blur-3xl flex flex-col fixed left-0 top-0 z-20">
          <div className="p-8 pb-12">
            <Link href="/" className="flex items-center gap-3 group">
              <div className="w-10 h-10 bg-indigo-500 rounded-xl flex items-center justify-center font-bold italic shadow-[0_0_20px_rgba(99,102,241,0.4)] group-hover:scale-110 transition-transform">
                Q
              </div>
              <span className="text-2xl font-black tracking-tighter">QuickEx</span>
            </Link>
          </div>
          
          <nav className="flex-1 px-4 space-y-2">
            <Link href="/dashboard" className="flex items-center gap-3 px-4 py-3 bg-white/5 border border-white/5 text-white rounded-2xl font-bold transition-all shadow-inner">
              <span className="text-indigo-400">📊</span>
              Dashboard
            </Link>
            <Link href="/generator" className="flex items-center gap-3 px-4 py-3 text-neutral-500 hover:text-white hover:bg-white/5 hover:translate-x-1 rounded-2xl font-semibold transition-all">
              <span>⚡</span>
              Link Generator
            </Link>
          </nav>

          <div className="p-6 m-4 mt-auto rounded-3xl bg-gradient-to-br from-neutral-900 to-black border border-white/5 shadow-2xl">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse shadow-[0_0_8px_#22c55e]" />
              <p className="text-[10px] font-bold text-neutral-500 uppercase tracking-widest leading-none">Wallet Connected</p>
            </div>
            <p className="text-xs font-mono text-neutral-300 truncate bg-black/40 p-2 rounded-lg border border-white/5">GA3D...R4N2</p>
          </div>
        </aside>

        <main className="flex-1 ml-72 p-12 relative z-10">
          <header className="mb-16 flex justify-between items-start">
            <div>
              <nav className="flex items-center gap-2 text-xs font-bold text-neutral-600 uppercase tracking-widest mb-4">
                <span>QuickEx</span>
                <span>/</span>
                <span className="text-neutral-400">Overview</span>
              </nav>
              <h1 className="text-5xl font-black tracking-tight mb-3">Welcome back.</h1>
              <p className="text-neutral-500 font-medium text-lg">Your global payments are scaling beautifully.</p>
            </div>
            
            <button className="px-6 py-3 bg-indigo-500 text-white font-bold rounded-2xl shadow-lg shadow-indigo-500/20 hover:scale-105 active:scale-95 transition-all">
              Withdraw Funds
            </button>
          </header>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 mb-16">
            <div className="relative group overflow-hidden p-8 rounded-[2rem] bg-neutral-900/40 border border-white/5 backdrop-blur-sm hover:border-indigo-500/30 transition-all duration-500">
              <div className="absolute top-0 right-0 p-4 opacity-10 group-hover:opacity-20 transition-opacity">
                <span className="text-6xl text-indigo-500 font-black tracking-tighter">$</span>
              </div>
              <p className="text-sm text-neutral-500 mb-2 font-bold uppercase tracking-wider">Total Revenue</p>
              <div className="flex items-baseline gap-2">
                <p className="text-5xl font-black tabular-nums tracking-tighter">$1,240.50</p>
                <span className="text-xs font-black text-green-500 bg-green-500/10 px-2 py-1 rounded-lg">+12.5%</span>
              </div>
            </div>

            <div className="p-8 rounded-[2rem] bg-neutral-900/40 border border-white/5 backdrop-blur-sm hover:border-indigo-500/30 transition-all duration-500">
              <p className="text-sm text-neutral-500 mb-2 font-bold uppercase tracking-wider">Success Rate</p>
              <p className="text-5xl font-black tabular-nums tracking-tighter">98.2%</p>
              <div className="mt-4 w-full h-1.5 bg-neutral-800 rounded-full overflow-hidden">
                <div className="w-[98%] h-full bg-indigo-500 shadow-[0_0_12px_rgba(99,102,241,0.5)]" />
              </div>
            </div>

            <div className="p-8 rounded-[2rem] bg-indigo-500 shadow-[0_20px_40px_-15px_rgba(99,102,241,0.3)] border border-indigo-400">
              <p className="text-sm text-indigo-100/60 mb-2 font-bold uppercase tracking-wider">Available Payout</p>
              <p className="text-5xl font-black tabular-nums tracking-tighter">850.00 <span className="text-2xl opacity-60 font-medium">USDC</span></p>
              <p className="text-xs text-indigo-100/40 mt-4 font-medium italic">Estimated settlement: 3 seconds</p>
            </div>
          </div>

          <div className="rounded-[2.5rem] bg-black/40 border border-white/5 backdrop-blur-2xl overflow-hidden shadow-2xl">
            <div className="p-10 border-b border-white/5 flex justify-between items-center">
              <div>
                <h2 className="text-2xl font-black mb-1">Activity Feed</h2>
                <p className="text-sm text-neutral-500 font-medium">Synced with Stellar Horizon API</p>
              </div>
              <div className="flex gap-3">
                <div className="bg-white/5 p-2 rounded-xl border border-white/5">
                  <select className="bg-transparent text-sm font-bold text-neutral-400 focus:outline-none">
                    <option>Last 30 Days</option>
                    <option>Yearly</option>
                  </select>
                </div>
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left">
                <thead>
                  <tr className="text-[10px] font-black text-neutral-600 uppercase tracking-[0.2em] border-b border-white/5">
                    <th className="px-10 py-6">Transaction ID</th>
                    <th className="px-10 py-6">Asset</th>
                    <th className="px-10 py-6">Memo / Reference</th>
                    <th className="px-10 py-6 text-right">Timestamp</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5 whitespace-nowrap">
                  {[
                    { id: "GD2P...5H2W", amount: "50.00 USDC", memo: "Project Milestone #1", date: "2 mins ago", status: "Privacy Enabled" },
                    { id: "GD1R...3K9L", amount: "125.00 XLM", memo: "Frontend Consulting", date: "Jan 20, 14:32", status: "Public" },
                    { id: "GC8T...9Q0M", amount: "20.00 USDC", memo: "Subscription Renewal", date: "Jan 19, 09:12", status: "Privacy Enabled" },
                  ].map((tx, i) => (
                    <tr key={i} className="group hover:bg-white/[0.02] transition-colors">
                      <td className="px-10 py-8">
                        <div className="flex items-center gap-3">
                          <span className="w-8 h-8 rounded-lg bg-white/5 flex items-center justify-center text-xs opacity-50 font-mono">#{i+1}</span>
                          <span className="font-mono text-neutral-400 group-hover:text-white transition-colors">{tx.id}</span>
                        </div>
                      </td>
                      <td className="px-10 py-8 font-black text-white text-lg">
                        {tx.amount}
                      </td>
                      <td className="px-10 py-8">
                        <div className="flex flex-col">
                          <span className="text-neutral-300 font-bold">{tx.memo}</span>
                          <span className={`text-[10px] uppercase font-black tracking-widest mt-1 ${tx.status.includes('Privacy') ? 'text-indigo-400' : 'text-neutral-600'}`}>
                            {tx.status}
                          </span>
                        </div>
                      </td>
                      <td className="px-10 py-8 text-neutral-500 text-right font-medium">
                        {tx.date}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            
            <div className="p-8 bg-white/[0.01] text-center">
              <button className="text-sm font-black text-neutral-500 hover:text-white transition-colors tracking-widest uppercase">
                View Full Ledger →
              </button>
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}
