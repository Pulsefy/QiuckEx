"use client";

import { useState } from "react";
import { MarketplaceListing, formatCountdown, placeBid } from "@/hooks/marketplaceApi";

type BidModalProps = {
  listing: MarketplaceListing | null;
  onClose: () => void;
  onBidSuccess: (username: string, amount: number) => void;
};

type BidState = "idle" | "loading" | "success" | "error";

export function BidModal({ listing, onClose, onBidSuccess }: BidModalProps) {
  const [amount, setAmount] = useState("");
  const [bidState, setBidState] = useState<BidState>("idle");
  const [errorMsg, setErrorMsg] = useState("");

  const minBid = listing ? listing.currentBid + 1 : 1;
  const parsedAmount = parseFloat(amount);
  const isValid = !isNaN(parsedAmount) && parsedAmount >= minBid;

  async function handleConfirm() {
    if (!listing || !isValid) return;
    setBidState("loading");
    setErrorMsg("");

    const result = await placeBid(listing.username, parsedAmount);
    if (result.success) {
      setBidState("success");
      onBidSuccess(listing.username, parsedAmount);
    } else {
      setBidState("error");
      setErrorMsg(result.reason);
    }
  }

  function handleClose() {
    setBidState("idle");
    setAmount("");
    setErrorMsg("");
    onClose();
  }

  if (!listing) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      {/* Blurred backdrop */}
      <div
        className="absolute inset-0 bg-black/70 backdrop-blur-md"
        onClick={bidState === "loading" ? undefined : handleClose}
      />

      <div className="relative z-10 w-full max-w-md">
        {/* Glow aura */}
        <div className="absolute -inset-1 bg-gradient-to-br from-indigo-500/30 via-purple-500/20 to-transparent rounded-3xl blur-xl pointer-events-none" />

        <div className="relative bg-neutral-900/90 border border-white/10 rounded-3xl p-8 shadow-2xl backdrop-blur-2xl">

          {/* ── SUCCESS STATE ─────────────────────────────── */}
          {bidState === "success" && (
            <div className="text-center py-4 space-y-5">
              <div className="text-6xl animate-bounce">🎉</div>
              <h2 className="text-2xl font-black">Bid Placed!</h2>
              <p className="text-neutral-400">
                You&apos;re leading with{" "}
                <span className="text-indigo-400 font-bold">{parsedAmount} USDC</span> on{" "}
                <span className="text-white font-bold">@{listing.username}</span>.
              </p>
              <div className="p-4 bg-indigo-500/10 rounded-2xl border border-indigo-500/20 text-left text-xs text-neutral-400 font-mono">
                <p className="font-bold text-indigo-400 mb-1">tx signed & broadcast ✓</p>
                <p>Network: Stellar Testnet</p>
                <p>Asset: USDC</p>
                <p>Amount: {parsedAmount}.00 USDC</p>
                <p>Ledger: ~2s settlement</p>
              </div>
              <button
                onClick={handleClose}
                className="w-full py-3 bg-indigo-500 text-white font-bold rounded-xl hover:bg-indigo-400 transition"
              >
                Done
              </button>
            </div>
          )}

          {/* ── IDLE / LOADING / ERROR STATES ─────────────── */}
          {bidState !== "success" && (
            <>
              {/* Header */}
              <div className="flex justify-between items-start mb-6">
                <div>
                  <p className="text-xs text-neutral-500 uppercase tracking-widest font-bold mb-1">
                    Place a Bid
                  </p>
                  <h2 className="text-2xl font-black tracking-tight">
                    @{listing.username}
                  </h2>
                </div>
                <button
                  onClick={handleClose}
                  disabled={bidState === "loading"}
                  className="w-9 h-9 rounded-full bg-white/5 border border-white/10 flex items-center justify-center text-neutral-400 hover:text-white hover:bg-white/10 transition"
                >
                  ✕
                </button>
              </div>

              {/* Stats row */}
              <div className="grid grid-cols-3 gap-3 mb-6">
                {[
                  { label: "Current Bid", value: `${listing.currentBid} USDC` },
                  { label: "Bids", value: listing.bidCount.toString() },
                  { label: "Ends In", value: formatCountdown(listing.endsAt) },
                ].map((s) => (
                  <div
                    key={s.label}
                    className="p-3 bg-white/5 rounded-2xl border border-white/5 text-center"
                  >
                    <p className="text-[10px] uppercase tracking-widest font-bold text-neutral-500 mb-1">
                      {s.label}
                    </p>
                    <p className="font-black text-sm">{s.value}</p>
                  </div>
                ))}
              </div>

              {/* Input */}
              <label className="block mb-2 text-xs font-bold uppercase tracking-widest text-neutral-500">
                Your Bid (USDC)
              </label>
              <div className="relative mb-4">
                <input
                  type="number"
                  min={minBid}
                  step="1"
                  placeholder={`Min ${minBid} USDC`}
                  value={amount}
                  onChange={(e) => setAmount(e.target.value)}
                  disabled={bidState === "loading"}
                  className="w-full bg-white/5 border border-white/10 focus:border-indigo-500/60 rounded-xl px-4 py-4 pr-20 font-bold text-white placeholder-neutral-600 outline-none transition text-lg"
                />
                <span className="absolute right-4 top-1/2 -translate-y-1/2 text-xs font-black text-indigo-400 tracking-widest">
                  USDC
                </span>
              </div>

              {/* Validation hint */}
              {amount && !isValid && (
                <p className="text-xs text-red-400 font-bold mb-3">
                  Bid must be at least {minBid} USDC
                </p>
              )}

              {/* Error */}
              {bidState === "error" && (
                <div className="mb-4 px-4 py-3 rounded-xl bg-red-500/10 border border-red-500/20 text-xs text-red-400 font-bold">
                  ⚠ {errorMsg}
                </div>
              )}

              {/* Wallet warning */}
              <div className="flex items-start gap-3 p-3 mb-5 bg-amber-500/5 border border-amber-500/15 rounded-2xl">
                <span className="text-amber-400 mt-0.5">🔑</span>
                <div className="text-[11px] text-amber-400/80 leading-relaxed">
                  <p className="font-bold mb-1">Wallet Connection Required</p>
                  <p>Confirming will request a signature from your Stellar wallet (Freighter/Lobstr). No funds will be deducted until auction ends.</p>
                </div>
              </div>

              {/* Bidding rules */}
              <div className="flex items-start gap-3 p-3 mb-5 bg-indigo-500/5 border border-indigo-500/15 rounded-2xl">
                <span className="text-indigo-400 mt-0.5">📋</span>
                <div className="text-[11px] text-indigo-400/80 leading-relaxed">
                  <p className="font-bold mb-1">Bidding Rules</p>
                  <ul className="space-y-0.5">
                    <li>• Minimum increment: +1 USDC above current bid</li>
                    <li>• Auction ends: {formatCountdown(listing.endsAt)}</li>
                    <li>• Winner pays highest bid amount</li>
                    <li>• Payment in USDC on Stellar network</li>
                  </ul>
                </div>
              </div>

              {/* CTA */}
              <button
                onClick={handleConfirm}
                disabled={!isValid || bidState === "loading"}
                className={`w-full py-4 rounded-xl font-black text-base tracking-wide transition-all ${
                  bidState === "loading"
                    ? "bg-indigo-500/40 text-white/60 cursor-wait"
                    : isValid
                    ? "bg-indigo-500 text-white hover:bg-indigo-400 shadow-[0_12px_40px_-15px_rgba(99,102,241,0.6)] hover:scale-[1.02] active:scale-[0.98]"
                    : "bg-white/5 text-neutral-600 cursor-not-allowed"
                }`}
              >
                {bidState === "loading" ? (
                  <span className="flex items-center justify-center gap-2">
                    <span className="inline-block w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                    Signing Transaction…
                  </span>
                ) : (
                  "Confirm Bid →"
                )}
              </button>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
