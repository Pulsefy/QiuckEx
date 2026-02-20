import Link from "next/link";
import { QRPreview } from "@/components/QRPreview";
import { NetworkBadge } from "@/components/NetworkBadge";

export default function Generator() {
  return (
    <div className="relative min-h-screen text-white selection:bg-indigo-500/30 overflow-x-hidden">
      <NetworkBadge />

     <div className="fixed top-[-20%] left-[-30%] w-[60%] h-[60%] bg-indigo-500/10 blur-[120px] rounded-full" />
      <div className="fixed bottom-[-20%] right-[-30%] w-[50%] h-[50%] bg-purple-500/5 blur-[100px] rounded-full" />

     

      {/* DESKTOP SIDEBAR */}
      <aside className="hidden md:flex w-72 h-screen border-r border-white/5 bg-black/20 backdrop-blur-3xl flex-col fixed left-0 top-0 z-20">
       

        <nav className="flex-1 px-4 py-30 space-y-2">
          <Link href="/dashboard" className="flex items-center gap-3 px-4 py-3 text-neutral-500 hover:text-white hover:bg-white/5 rounded-2xl font-semibold">
            <span>📊</span> Dashboard
          </Link>
          <Link href="/generator" className="flex items-center gap-3 px-4 py-3 bg-white/5 text-white rounded-2xl font-bold border border-white/5 shadow-inner">
            <span className="text-indigo-400">⚡</span> Link Generator
          </Link>
        </nav>
      </aside>

      {/* MAIN */}
      <main className="relative z-10 px-4 sm:px-6 md:px-12 pt-10 md:ml-72 overflow-x-hidden">

        {/* HEADER */}
        <header className="mb-10 sm:mb-16 max-w-3xl">
          <nav className="flex items-center gap-2 text-xs font-bold text-neutral-600 uppercase tracking-widest mb-3 sm:mb-6">
            <span>Services</span>
            <span>/</span>
            <span className="text-neutral-400">Link Generator</span>
          </nav>

          <h1 className="text-4xl sm:text-5xl md:text-6xl font-black leading-tight tracking-tighter mb-4">
            Create a payment <br />
            <span className="bg-gradient-to-r from-indigo-400 to-purple-400 bg-clip-text text-transparent">
              request instantly.
            </span>
          </h1>

          <p className="text-neutral-500 text-base sm:text-lg md:text-xl max-w-xl">
            Set your parameters, enable privacy if needed, and share your unique link with the world.
          </p>
        </header>

        {/* GRID — STACKS ON MOBILE */}
        <div className="grid grid-cols-1 xl:grid-cols-[1.2fr_0.8fr] gap-10 sm:gap-12 xl:gap-20 max-w-7xl">

          {/* LEFT COLUMN (FORM) */}
          <div className="space-y-12">

            {/* Transaction Section */}
            <section className="space-y-6">
              <div className="flex items-center justify-between px-1">
                <label className="text-xs font-black text-neutral-500 uppercase tracking-[0.2em]">
                  Transaction Details
                </label>
                <span className="text-[10px] font-bold text-indigo-400/60 bg-indigo-400/5 px-2 py-1 rounded-md uppercase">
                  Stellar L1
                </span>
              </div>

              {/* Amount Input */}
              <div className="relative group">
                <div className="absolute -inset-0.5 bg-gradient-to-r from-indigo-500/20 to-purple-500/20 rounded-3xl blur opacity-0 group-focus-within:opacity-100 transition" />

                <div className="relative bg-neutral-900/50 border border-white/10 rounded-3xl p-1 shadow-2xl backdrop-blur-xl">
                  <input
                    type="number"
                    placeholder="0.00"
                    className="
                      w-full bg-transparent 
                      p-6 sm:p-8 
                      text-3xl sm:text-5xl 
                      font-black 
                      placeholder:text-neutral-800 
                      focus:outline-none
                    "
                  />

                  {/* Currency Toggle */}
                  <div className="
                    absolute right-3 sm:right-6 
                    top-1/2 -translate-y-1/2 
                    flex bg-black/40 
                    p-1 sm:p-2 
                    rounded-2xl border border-white/5 
                    backdrop-blur-xl gap-1
                  ">
                    <button className="px-4 sm:px-6 py-2 sm:py-3 bg-white text-black text-xs sm:text-sm font-black rounded-xl shadow-md hover:scale-105 transition">
                      USDC
                    </button>
                    <button className="px-3 sm:px-6 py-2 sm:py-3 text-neutral-500 text-xs sm:text-sm font-bold hover:text-white transition">
                      XLM
                    </button>
                  </div>
                </div>
              </div>

              {/* Memo Input */}
              <div className="relative group">
                <div className="absolute -inset-0.5 bg-indigo-500/10 rounded-3xl blur opacity-0 group-focus-within:opacity-100 transition" />
                <input
                  type="text"
                  placeholder="What's this payment for? (e.g. Logo Design)"
                  className="
                    w-full 
                    bg-neutral-900/30 
                    border border-white/5 
                    rounded-3xl 
                    p-6 sm:p-8 
                    text-lg sm:text-xl 
                    font-bold 
                    shadow-inner 
                    placeholder:text-neutral-700 
                    focus:outline-none
                  "
                />
              </div>
            </section>

            {/* Privacy Section */}
            <section className="p-6 sm:p-10 rounded-3xl bg-gradient-to-br from-indigo-500/10 to-transparent border border-indigo-500/20 shadow-2xl relative overflow-hidden">
              <div className="absolute top-0 right-0 p-6 sm:p-8 opacity-10">
                <span className="text-6xl sm:text-7xl">🛡️</span>
              </div>

              <div className="flex items-start justify-between gap-4 mb-8">
                <div className="max-w-sm">
                  <h3 className="text-xl sm:text-2xl font-black mb-2">X-Ray Privacy</h3>
                  <p className="text-neutral-400 text-sm sm:text-base">
                    Enable zero-knowledge proofs to shield the transaction amount.
                  </p>
                </div>

                <div className="w-14 sm:w-16 h-7 sm:h-8 bg-neutral-800 rounded-full relative p-1 cursor-pointer ring-4 ring-indigo-500/20">
                  <div className="w-5 sm:w-6 h-5 sm:h-6 bg-white/20 rounded-full shadow-lg" />
                </div>
              </div>

              <div className="flex flex-wrap gap-3 sm:gap-4">
                <span className="px-3 sm:px-4 py-2 bg-indigo-500/10 border border-indigo-500/20 rounded-xl text-[10px] font-black uppercase tracking-widest text-indigo-400">
                  WASM Optimized
                </span>

                <span className="px-3 sm:px-4 py-2 bg-white/5 border border-white/5 rounded-xl text-[10px] font-black uppercase tracking-widest text-neutral-500">
                  ZK-Proof Powered
                </span>
              </div>
            </section>

            {/* Generate Button */}
            <button className="
              w-full py-6 sm:py-10 
              bg-white text-black 
              font-black 
              text-2xl sm:text-3xl 
              rounded-3xl 
              hover:bg-neutral-200 
              hover:scale-[1.01] 
              active:scale-95 
              transition 
              shadow-[0_20px_50px_rgba(255,255,255,0.1)]
            ">
              Generate Payment Link
            </button>
          </div>

          {/* RIGHT COLUMN */}
          <div className="space-y-12">

            {/* QR Preview */}
            <div className="relative flex justify-center">
              <div className="w-full max-w-xs sm:max-w-sm mx-auto">
                <QRPreview />
              </div>
            </div>

            {/* Share Panel */}
            <div className="space-y-6 sm:space-y-8 p-6 sm:p-10 rounded-3xl bg-black/40 border border-white/5 backdrop-blur-xl">
              
              <div className="space-y-4">
                <label className="text-[10px] text-neutral-600 font-black uppercase tracking-[0.25em]">
                  Universal Share Link
                </label>

                <div className="flex flex-col sm:flex-row gap-3">
                  <div className="flex-1 bg-neutral-900 border border-white/5 rounded-2xl p-4 sm:p-5 font-mono text-xs sm:text-sm text-neutral-600 truncate italic">
                    quickex.to/ga3d/payment_...
                  </div>

                  <button className="px-4 sm:px-6 py-4 sm:py-5 bg-white/5 text-neutral-500 border border-white/5 rounded-2xl font-black text-xs uppercase opacity-30 cursor-not-allowed">
                    Copy
                  </button>
                </div>
              </div>

              {/* Buttons */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <button className="p-4 bg-white/5 hover:bg-white/10 border border-white/5 rounded-2xl text-xs font-black uppercase tracking-widest transition">
                  Save Image
                </button>
                <button className="p-4 bg-white/5 hover:bg-white/10 border border-white/5 rounded-2xl text-xs font-black uppercase tracking-widest transition">
                  Download PDF
                </button>
              </div>
            </div>

          </div>

        </div>
      </main>
    </div>
  );
}
