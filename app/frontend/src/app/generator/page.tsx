"use client";

import { useState } from "react";
import Link from "next/link";
import { QRPreview } from "@/components/QRPreview";
import { NetworkBadge } from "@/components/NetworkBadge";
import { mockFetch } from "@/hooks/mockApi";
import { useApi } from "@/hooks/useApi";

export default function Generator() {
const { data, error, loading, callApi } = useApi();


  
  const [form, setForm] = useState({
    amount: "",
    asset: "USDC",
    destination: "",
    memo: "",
  });

  const [errors, setErrors] = useState<any>({});

  // Validation logic
  const validate = () => {
    const newErrors: any = {};

    if (!form.amount) newErrors.amount = "Amount is required.";
    else if (isNaN(Number(form.amount))) newErrors.amount = "Enter a valid number.";

    if (!form.destination) newErrors.destination = "Destination address is required.";

    if (!form.asset) newErrors.asset = "Select an asset.";

    return newErrors;
  };

  const linkData =
  form.amount && form.asset && form.destination
    ? JSON.stringify(form)
    : "";

  const handleSubmit = () => {
      callApi(() => mockFetch({ link: "https://quickex/pay/123" }));
    const validation = validate();
    setErrors(validation);

    if (Object.keys(validation).length === 0) {
      console.log("VALID FORM:", form);
    }
  };

  return (
    <div className="relative min-h-screen text-white selection:bg-indigo-500/30 overflow-x-hidden">
      <NetworkBadge />

      {/* BACKGROUND */}
      <div className="fixed top-[-20%] left-[-30%] w-[60%] h-[60%] bg-indigo-500/10 blur-[120px]" />
      <div className="fixed bottom-[-20%] right-[-30%] w-[50%] h-[50%] bg-purple-500/5 blur-[100px]" />

      {/* DESKTOP SIDEBAR */}
      <aside className="hidden md:flex w-72 h-screen border-r border-white/5 bg-black/20 backdrop-blur-3xl flex-col fixed left-0 top-0 z-20">
        <nav className="flex-1 px-4 py-20 space-y-2">
          <Link href="/dashboard" className="flex items-center gap-3 px-4 py-3 text-neutral-500 hover:text-white hover:bg-white/5 rounded-2xl font-semibold">
            <span>📊</span> Dashboard
          </Link>
          <Link href="/generator" className="flex items-center gap-3 px-4 py-3 bg-white/5 text-white rounded-2xl font-bold border border-white/5 shadow-inner">
            <span className="text-indigo-400">⚡</span> Link Generator
          </Link>
        </nav>
      </aside>

      {/* MAIN */}
      <main className="relative z-10 px-4 sm:px-6 md:px-12 pt-10 md:ml-72">

        {/* HEADER */}
        <header className="mb-10 sm:mb-16 max-w-3xl">
          <nav className="flex items-center gap-2 text-xs font-black text-neutral-600 uppercase tracking-widest mb-4">
            <span>Services</span>
            <span>/</span>
            <span className="text-neutral-400">Link Generator</span>
          </nav>

          <h1 className="text-4xl sm:text-5xl md:text-6xl font-black tracking-tight mb-4">
            Create a payment <br />
            <span className="bg-gradient-to-r from-indigo-400 to-purple-400 bg-clip-text text-transparent">
              request instantly.
            </span>
          </h1>

          <p className="text-neutral-500 text-lg max-w-xl">
            Set your parameters, enable privacy if needed, and share your unique link with the world.
          </p>
        </header>

        {/* GRID */}
        <div className="grid grid-cols-1 xl:grid-cols-[1.2fr_0.8fr] gap-12 xl:gap-20 max-w-7xl">

          {/* FORM COLUMN */}
          <div className="space-y-12">

            {/* Transaction Section */}
            <section className="space-y-6">

              {/* Amount Input */}
              <div>
                <label className="text-xs font-black uppercase tracking-widest text-neutral-500 ml-1">Amount</label>

                <div className="relative group mt-2">
                  <div className="absolute -inset-0.5 bg-gradient-to-r from-indigo-500/20 to-purple-500/20 rounded-3xl blur opacity-0 group-focus-within:opacity-100 transition" />

                  <div className="relative bg-neutral-900/50 border border-white/10 rounded-3xl p-1 shadow-2xl">
                    <input
                      type="number"
                      placeholder="0.00"
                      value={form.amount}
                      onChange={(e) => setForm({ ...form, amount: e.target.value })}
                      className="w-full bg-transparent p-6 sm:p-8 text-3xl sm:text-5xl font-black focus:outline-none placeholder:text-neutral-800"
                    />

                    {/* Asset Buttons */}
                    <div className="absolute right-4 top-1/2 -translate-y-1/2 flex bg-black/40 p-2 rounded-2xl border border-white/5 backdrop-blur-xl gap-1">
                      {["USDC", "XLM"].map((asset) => (
                        <button
                          key={asset}
                          onClick={() => setForm({ ...form, asset })}
                          className={`
                            px-4 py-2 text-xs sm:text-sm rounded-xl transition 
                            ${form.asset === asset ? "bg-white text-black font-black" : "text-neutral-500 hover:text-white"}
                          `}
                        >
                          {asset}
                        </button>
                      ))}
                    </div>
                  </div>
                </div>

                {errors.amount && (
                  <p className="text-red-500 text-xs mt-2">{errors.amount}</p>
                )}
              </div>

              {/* Destination Input */}
              <div>
                <label className="text-xs font-black uppercase tracking-widest text-neutral-500 ml-1">Destination</label>
                <input
                  type="text"
                  placeholder="Receiver public key"
                  value={form.destination}
                  onChange={(e) => setForm({ ...form, destination: e.target.value })}
                  className="w-full bg-neutral-900/30 border border-white/10 rounded-3xl p-5 font-bold mt-2 focus:outline-none placeholder:text-neutral-700"
                />
                {errors.destination && (
                  <p className="text-red-500 text-xs mt-2">{errors.destination}</p>
                )}
              </div>

              {/* Memo Input */}
              <div>
                <label className="text-xs font-black uppercase tracking-widest text-neutral-500 ml-1">Memo (optional)</label>
                <input
                  type="text"
                  placeholder="What's this payment for?"
                  value={form.memo}
                  onChange={(e) => setForm({ ...form, memo: e.target.value })}
                  className="w-full bg-neutral-900/30 border border-white/10 rounded-3xl p-5 font-bold mt-2 focus:outline-none placeholder:text-neutral-700"
                />
              </div>

            </section>

            <button
              onClick={handleSubmit} disabled={loading}
              className="w-full py-6 bg-white text-black text-3xl font-black rounded-3xl hover:bg-neutral-200 active:scale-95 transition"
            >
              {loading ? "Generating..." : "Generate Payment Link"}
              {error && <p className="text-red-500">{error}</p>}

            
            </button>
          </div>

          {/* RIGHT COLUMN */}
          <div className="space-y-12">

            <div className="w-full max-w-sm mx-auto">
              <QRPreview value={linkData} />
            </div>

            {/* Share Panel */}
            <div className="space-y-4 p-8 rounded-3xl bg-black/40 border border-white/5 backdrop-blur-xl">
              <label className="text-[10px] font-black uppercase tracking-widest text-neutral-600">
                Universal Share Link
              </label>

              <div className="bg-neutral-900 border border-white/5 p-4 rounded-xl font-mono text-neutral-500 text-sm italic truncate">
                quickex.to/ga3d/payment_...
              </div>

              <button className="w-full py-3 bg-white/10 text-neutral-500 rounded-xl border border-white/5 text-xs uppercase tracking-widest cursor-not-allowed">
                Copy
              </button>
            </div>

          </div>

        </div>
      </main>
    </div>
  );
}