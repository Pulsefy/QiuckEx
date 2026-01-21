import { NetworkBadge } from "@/components/NetworkBadge";
import Link from "next/link";

export default function Home() {
  return (
    <div className="min-h-screen bg-neutral-950 text-white selection:bg-indigo-500/30">
      <NetworkBadge />
      
      {/* Navigation */}
      <nav className="container mx-auto px-6 py-8 flex justify-between items-center border-b border-white/5">
        <div className="flex items-center gap-2">
          <div className="w-8 h-8 bg-indigo-500 rounded-lg flex items-center justify-center font-bold italic shadow-lg shadow-indigo-500/20">
            Q
          </div>
          <span className="text-xl font-bold tracking-tight">QuickEx</span>
        </div>
        <div className="flex gap-8 text-sm font-medium text-neutral-400">
          <Link href="/dashboard" className="hover:text-white transition-colors">Dashboard</Link>
          <Link href="/generator" className="hover:text-white transition-colors">Generator</Link>
        </div>
      </nav>

      {/* Hero Section */}
      <main className="container mx-auto px-6 pt-24 pb-32">
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

        {/* Feature Grid */}
        <div className="grid md:grid-cols-3 gap-8 mt-48">
          <div className="p-8 rounded-3xl bg-neutral-900/50 border border-white/5 hover:border-indigo-500/20 transition-colors group">
            <div className="w-12 h-12 bg-indigo-500/10 rounded-2xl flex items-center justify-center mb-6 group-hover:bg-indigo-500/20 transition-colors">
              <span className="text-2xl">👤</span>
            </div>
            <h3 className="text-xl font-bold mb-4 text-white">Shareable Usernames</h3>
            <p className="text-neutral-400 leading-relaxed">Claim your unique name like quickex.to/alex and receive payments easily.</p>
          </div>
          <div className="p-8 rounded-3xl bg-neutral-900/50 border border-white/5 hover:border-indigo-500/20 transition-colors group">
            <div className="w-12 h-12 bg-indigo-500/10 rounded-2xl flex items-center justify-center mb-6 group-hover:bg-indigo-500/20 transition-colors">
              <span className="text-2xl">🛡️</span>
            </div>
            <h3 className="text-xl font-bold mb-4 text-white">X-Ray Privacy</h3>
            <p className="text-neutral-400 leading-relaxed">Toggle privacy mode to shield transaction amounts using ZK-proofs.</p>
          </div>
          <div className="p-8 rounded-3xl bg-neutral-900/50 border border-white/5 hover:border-indigo-500/20 transition-colors group">
            <div className="w-12 h-12 bg-indigo-500/10 rounded-2xl flex items-center justify-center mb-6 group-hover:bg-indigo-500/20 transition-colors">
              <span className="text-2xl">⚡</span>
            </div>
            <h3 className="text-xl font-bold mb-4 text-white">Instant Settlement</h3>
            <p className="text-neutral-400 leading-relaxed">Finalize global transfers in sub-seconds with fees less than 0.01¢.</p>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="container mx-auto px-6 py-12 border-t border-white/5 text-neutral-500 text-sm">
        <div className="flex flex-col md:row justify-between items-center gap-8">
          <p>© 2026 QuickEx Platform. Built by Pulsefy.</p>
          <div className="flex gap-8 underline underline-offset-4 decoration-white/10 hover:decoration-white/20 transition-colors">
            <a href="https://github.com/pulsefy/QuickEx" target="_blank">GitHub</a>
            <a href="#">Terms</a>
            <a href="#">Privacy</a>
          </div>
        </div>
      </footer>
    </div>
  );
}
