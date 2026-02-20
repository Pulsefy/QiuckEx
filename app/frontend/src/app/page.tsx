import { NetworkBadge } from "@/components/NetworkBadge";
import Link from "next/link";

export default function Home() {
  return (
    <div className="selection:bg-indigo-500/30">
      <NetworkBadge />

      <section className="pt-20 md:pt-32 pb-32">
        <div className="max-w-3xl">
          <h1 className="text-6xl md:text-7xl font-bold tracking-tighter mb-8 bg-gradient-to-br from-white to-neutral-500 bg-clip-text text-transparent leading-tight">
            Privacy-focused <br /> payments on Stellar.
          </h1>

          <p className="text-xl text-neutral-400 mb-12 leading-relaxed max-w-xl">
            Create unique, shareable usernames and generate instant payment requests for USDC or XLM. 
            Powered by Soroban smart contracts for shielded transactions.
          </p>

          <div className="flex flex-col sm:flex-row gap-4">
            <Link 
              href="/generator" 
              className="px-8 py-4 bg-white text-black font-bold rounded-xl hover:bg-neutral-200 transition-all text-center shadow-xl shadow-white/5"
            >
              Generate Link
            </Link>

            <Link 
              href="/dashboard" 
              className="px-8 py-4 bg-neutral-900 text-white font-bold rounded-xl hover:bg-neutral-800 transition-all border border-white/10 text-center"
            >
              Go to Dashboard
            </Link>
          </div>
        </div>

       
        <div className="grid md:grid-cols-3 gap-8 mt-32 md:mt-48">
          <div className="p-8 rounded-3xl bg-neutral-900/50 border border-white/5 hover:border-indigo-500/20 transition-colors group">
            <div className="w-12 h-12 bg-indigo-500/10 rounded-2xl flex items-center justify-center mb-6 group-hover:bg-indigo-500/20 transition">
              <span className="text-2xl">👤</span>
            </div>
            <h3 className="text-xl font-bold mb-4">Shareable Usernames</h3>
            <p className="text-neutral-400">Claim your unique name like quickex.to/alex and receive payments easily.</p>
          </div>

          <div className="p-8 rounded-3xl bg-neutral-900/50 border border-white/5 hover:border-indigo-500/20 transition-colors group">
            <div className="w-12 h-12 bg-indigo-500/10 rounded-2xl flex items-center justify-center mb-6 group-hover:bg-indigo-500/20 transition">
              <span className="text-2xl">🛡️</span>
            </div>
            <h3 className="text-xl font-bold mb-4">X-Ray Privacy</h3>
            <p className="text-neutral-400">Toggle privacy mode to shield transaction amounts using ZK-proofs.</p>
          </div>

          <div className="p-8 rounded-3xl bg-neutral-900/50 border border-white/5 hover:border-indigo-500/20 transition-colors group">
            <div className="w-12 h-12 bg-indigo-500/10 rounded-2xl flex items-center justify-center mb-6 group-hover:bg-indigo-500/20 transition">
              <span className="text-2xl">⚡</span>
            </div>
            <h3 className="text-xl font-bold mb-4">Instant Settlement</h3>
            <p className="text-neutral-400">Finalize global transfers in sub-seconds with fees less than 0.01¢.</p>
          </div>
        </div>
      </section>
    </div>
  );
}
