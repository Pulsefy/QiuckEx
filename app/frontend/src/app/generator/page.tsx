import Link from "next/link";
import { QRPreview } from "@/components/QRPreview";
import { NetworkBadge } from "@/components/NetworkBadge";

export default function Generator() {
  return (
    <div className="min-h-screen bg-neutral-950 text-white selection:bg-indigo-500/30 overflow-x-hidden font-sans">
      <NetworkBadge />
      
      <div className="flex min-h-screen relative">
        {/* Background Accents */}
        <div className="fixed top-[-5%] right-[-5%] w-[40%] h-[40%] bg-indigo-500/5 blur-[120px] rounded-full" />
        <div className="fixed bottom-0 left-[10%] w-[30%] h-[30%] bg-white/5 blur-[100px] rounded-full" />

        {/* Premium Sidebar */}
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
            <Link href="/dashboard" className="flex items-center gap-3 px-4 py-3 text-neutral-500 hover:text-white hover:bg-white/5 hover:translate-x-1 rounded-2xl font-semibold transition-all">
              <span>📊</span>
              Dashboard
            </Link>
            <Link href="/generator" className="flex items-center gap-3 px-4 py-3 bg-white/5 border border-white/5 text-white rounded-2xl font-bold transition-all shadow-inner">
              <span className="text-indigo-400">⚡</span>
              Link Generator
            </Link>
          </nav>
        </aside>

        {/* Main Content Area */}
        <main className="flex-1 ml-72 p-12 relative z-10">
          <header className="mb-20 max-w-4xl px-4">
            <nav className="flex items-center gap-2 text-xs font-bold text-neutral-600 uppercase tracking-widest mb-6">
              <span>Services</span>
              <span>/</span>
              <span className="text-neutral-400">Link Generator</span>
            </nav>
            <h1 className="text-6xl font-black tracking-tighter mb-4 leading-tight">
              Create a payment <br /> 
              <span className="bg-gradient-to-r from-indigo-400 to-purple-400 bg-clip-text text-transparent">request instantly.</span>
            </h1>
            <p className="text-neutral-500 font-medium text-xl max-w-2xl">
              Set your parameters, enable privacy if needed, and share your unique link with the world.
            </p>
          </header>

          <div className="grid xl:grid-cols-[1.2fr_0.8fr] gap-20 px-4 max-w-7xl">
            {/* High-Fidelity Form Section */}
            <div className="space-y-12">
              <section className="space-y-6">
                <div className="flex items-center justify-between px-2">
                  <label className="text-xs font-black text-neutral-500 uppercase tracking-[0.2em]">Transaction Details</label>
                  <span className="text-[10px] font-bold text-indigo-400/60 bg-indigo-400/5 px-2 py-1 rounded-md uppercase tracking-widest">Stellar L1</span>
                </div>
                
                <div className="relative group">
                  <div className="absolute -inset-0.5 bg-gradient-to-r from-indigo-500/20 to-purple-500/20 rounded-[2.5rem] blur opacity-0 group-focus-within:opacity-100 transition-opacity" />
                  <div className="relative bg-neutral-900/50 border border-white/10 rounded-[2.5rem] p-1 shadow-2xl backdrop-blur-xl">
                    <input 
                      type="number" 
                      placeholder="0.00" 
                      className="w-full bg-transparent p-10 text-5xl font-black focus:outline-none placeholder:text-neutral-800 tabular-nums tracking-tighter" 
                    />
                    <div className="absolute right-8 top-1/2 -translate-y-1/2 flex bg-black/40 p-2 rounded-2xl border border-white/5 backdrop-blur-xl">
                      <button className="px-6 py-3 bg-white text-black text-sm font-black rounded-xl shadow-xl hover:scale-105 transition-transform">USDC</button>
                      <button className="px-6 py-3 text-neutral-500 text-sm font-bold hover:text-white transition-colors">XLM</button>
                    </div>
                  </div>
                </div>

                <div className="relative group">
                  <div className="absolute -inset-0.5 bg-indigo-500/10 rounded-3xl blur opacity-0 group-focus-within:opacity-100 transition-opacity" />
                  <input 
                    type="text" 
                    placeholder="What's this payment for? (e.g. Logo Design)" 
                    className="relative w-full bg-neutral-900/30 border border-white/5 rounded-3xl p-8 text-xl font-bold focus:outline-none focus:border-white/10 transition-all placeholder:text-neutral-700 shadow-inner" 
                  />
                </div>
              </section>

              {/* Advanced Controls */}
              <section className="p-10 rounded-[3rem] bg-gradient-to-br from-indigo-500/10 to-transparent border border-indigo-500/20 shadow-2xl relative overflow-hidden group">
                <div className="absolute top-0 right-0 p-8 opacity-10 group-hover:rotate-12 transition-transform duration-700">
                  <span className="text-7xl">🛡️</span>
                </div>
                
                <div className="flex items-center justify-between mb-8">
                  <div>
                    <h3 className="text-2xl font-black text-white mb-2">X-Ray Privacy</h3>
                    <p className="text-neutral-400 font-medium max-w-sm">Enable zero-knowledge proofs to shield the transaction amount from public ledgers.</p>
                  </div>
                  <div className="w-16 h-8 bg-neutral-800 rounded-full relative p-1 cursor-pointer ring-4 ring-indigo-500/20">
                     <div className="w-6 h-6 bg-white/20 rounded-full shadow-lg" />
                  </div>
                </div>
                
                <div className="flex gap-4">
                   <span className="px-4 py-2 bg-indigo-500/10 border border-indigo-500/20 rounded-xl text-[10px] font-black text-indigo-400 uppercase tracking-widest">WASM Optimized</span>
                   <span className="px-4 py-2 bg-white/5 border border-white/5 rounded-xl text-[10px] font-black text-neutral-500 uppercase tracking-widest">ZK-Proof Powered</span>
                </div>
              </section>

              <button className="w-full py-10 bg-white text-black font-black text-3xl rounded-[2.5rem] hover:bg-neutral-200 hover:scale-[1.01] active:scale-95 transition-all shadow-[0_20px_50px_rgba(255,255,255,0.1)]">
                Generate Payment Link
              </button>
            </div>

            {/* Premium Preview Section */}
            <div className="space-y-12">
               <div className="relative">
                  {/* Decorative element */}
                  <div className="absolute -top-10 -left-10 w-20 h-20 border-t-4 border-l-4 border-indigo-500/20 rounded-tl-[3rem]" />
                  <div className="absolute -bottom-10 -right-10 w-20 h-20 border-b-4 border-r-4 border-indigo-500/20 rounded-br-[3rem]" />
                  
                  <QRPreview />
               </div>

               <div className="space-y-8 p-10 rounded-[2.5rem] bg-black/40 border border-white/5 backdrop-blur-xl">
                  <div className="space-y-4">
                    <label className="text-[10px] font-black text-neutral-600 uppercase tracking-[0.3em] ml-1">Universal Share Link</label>
                    <div className="flex gap-3">
                      <div className="flex-1 bg-neutral-900 border border-white/5 rounded-2xl p-5 font-mono text-sm text-neutral-600 truncate italic">
                        quickex.to/ga3d/payment_...
                      </div>
                      <button className="px-6 py-5 bg-white/5 text-neutral-500 rounded-2xl font-black text-xs uppercase tracking-widest cursor-not-allowed opacity-30 border border-white/5">Copy</button>
                    </div>
                  </div>
                  
                  <div className="grid grid-cols-2 gap-4">
                    <button className="p-4 bg-white/5 hover:bg-white/10 rounded-2xl text-xs font-black uppercase tracking-widest transition-colors border border-white/5">Save Image</button>
                    <button className="p-4 bg-white/5 hover:bg-white/10 rounded-2xl text-xs font-black uppercase tracking-widest transition-colors border border-white/5">Download PDF</button>
                  </div>
               </div>
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}
