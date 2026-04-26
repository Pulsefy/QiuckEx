"use client";

import { AlertTriangle, Clock, ShieldCheck, Wallet } from "lucide-react";

export type SigningAction = "bid" | "refund" | "dispute" | "listing" | "purchase";

interface SigningSummaryProps {
  action: SigningAction;
  amount?: {
    value: number;
    asset: string;
  };
  details: {
    label: string;
    value: string;
  }[];
  expiry?: Date;
  network?: string;
  targetNetwork?: string;
}

export function SigningSummary({
  action,
  amount,
  details,
  expiry,
  network = "Stellar Testnet",
  targetNetwork = "Stellar Testnet",
}: SigningSummaryProps) {
  const isNetworkMismatch = network !== targetNetwork;
  const isExpired = expiry ? expiry.getTime() < Date.now() : false;

  const actionLabels: Record<SigningAction, string> = {
    bid: "Place Auction Bid",
    refund: "Request Refund",
    dispute: "Open Dispute",
    listing: "Create Listing",
    purchase: "Buy Now",
  };

  return (
    <div className="space-y-4 animate-in fade-in slide-in-from-bottom-2 duration-300">
      {/* Action Header */}
      <div className="flex items-center gap-3 p-4 bg-indigo-500/10 border border-indigo-500/20 rounded-2xl">
        <div className="w-10 h-10 rounded-full bg-indigo-500/20 flex items-center justify-center text-indigo-400">
          <ShieldCheck size={20} />
        </div>
        <div>
          <p className="text-[10px] uppercase tracking-widest font-black text-indigo-400/70">
            Secure Signing Request
          </p>
          <h3 className="text-lg font-black text-white">{actionLabels[action]}</h3>
        </div>
      </div>

      {/* Main Summary Card */}
      <div className="bg-white/5 border border-white/10 rounded-2xl overflow-hidden">
        {/* Amount Section if applicable */}
        {amount && (
          <div className="p-6 text-center border-b border-white/5 bg-gradient-to-b from-white/[0.02] to-transparent">
            <p className="text-xs font-bold text-neutral-500 uppercase tracking-widest mb-1">
              Transaction Value
            </p>
            <div className="flex items-center justify-center gap-2">
              <span className="text-3xl font-black text-white">{amount.value}</span>
              <span className="text-lg font-bold text-indigo-400">{amount.asset}</span>
            </div>
          </div>
        )}

        {/* Detail Rows */}
        <div className="p-4 space-y-3">
          {details.map((detail, i) => (
            <div key={i} className="flex justify-between items-center text-sm">
              <span className="text-neutral-500 font-medium">{detail.label}</span>
              <span className="text-white font-bold font-mono text-xs">{detail.value}</span>
            </div>
          ))}

          {/* Network Row */}
          <div className="flex justify-between items-center text-sm pt-2 border-t border-white/5">
            <span className="text-neutral-500 font-medium flex items-center gap-1.5">
              <Wallet size={14} /> Network
            </span>
            <span className={`font-bold ${isNetworkMismatch ? "text-red-400" : "text-neutral-300"}`}>
              {network}
            </span>
          </div>

          {/* Expiry Row */}
          {expiry && (
            <div className="flex justify-between items-center text-sm">
              <span className="text-neutral-500 font-medium flex items-center gap-1.5">
                <Clock size={14} /> Quote Expiry
              </span>
              <span className={`font-bold ${isExpired ? "text-red-400" : "text-emerald-400"}`}>
                {isExpired ? "Expired" : "Valid"}
              </span>
            </div>
          )}
        </div>
      </div>

      {/* Warnings */}
      {(isNetworkMismatch || isExpired) && (
        <div className="p-4 bg-red-500/10 border border-red-500/20 rounded-2xl space-y-2">
          <div className="flex items-center gap-2 text-red-400 font-black text-xs uppercase tracking-tight">
            <AlertTriangle size={16} /> Attention Required
          </div>
          <ul className="text-xs text-red-400/80 space-y-1 list-disc list-inside">
            {isNetworkMismatch && (
              <li>Your wallet is on {network}, but this action requires {targetNetwork}.</li>
            )}
            {isExpired && (
              <li>This transaction payload has expired. Please refresh the quote.</li>
            )}
          </ul>
        </div>
      )}

      {!isNetworkMismatch && !isExpired && (
        <p className="text-[10px] text-neutral-500 text-center px-4 leading-relaxed italic">
          Verify the details above match your intention. This action will request a cryptographic signature from your connected wallet.
        </p>
      )}
    </div>
  );
}
