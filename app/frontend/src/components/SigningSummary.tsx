"use client";

import { AlertTriangle, Clock, ShieldCheck, Wallet } from "lucide-react";

export type SigningAction = "bid" | "refund" | "dispute" | "listing" | "purchase";

interface SigningFee {
  value: number;
  asset: string;
  label?: string;
  percentage?: number;
  thresholdPercent?: number;
  isHigh?: boolean;
}

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
  fee?: SigningFee;
}

export function SigningSummary({
  action,
  amount,
  details,
  expiry,
  network = "Stellar Testnet",
  targetNetwork = "Stellar Testnet",
  fee,
}: SigningSummaryProps) {
  const isNetworkMismatch = network !== targetNetwork;
  const isExpired = expiry ? expiry.getTime() < Date.now() : false;

  const feeThreshold = fee?.thresholdPercent ?? 3;
  const feePercentage = fee?.percentage ?? (fee && amount ? (amount.value > 0 ? (fee.value / amount.value) * 100 : 0) : undefined);
  const isHighFee = Boolean(fee?.isHigh || (feePercentage !== undefined && feePercentage >= feeThreshold));

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
          <h3 className="text-lg font-black text-foreground">{actionLabels[action]}</h3>
        </div>
      </div>

      {/* Main Summary Card */}
      <div className="bg-surface border border-border-strong rounded-2xl overflow-hidden">
        {amount && (
          <div className="p-6 text-center border-b border-border bg-gradient-to-b from-white/[0.02] to-transparent">
            <p className="text-xs font-bold text-subtle uppercase tracking-widest mb-1">
              Transaction Value
            </p>
            <div className="flex items-center justify-center gap-2">
              <span className="text-3xl font-black text-foreground">{amount.value}</span>
              <span className="text-lg font-bold text-indigo-400">{amount.asset}</span>
            </div>
          </div>
        )}

        <div className="p-4 space-y-3">
          {details.map((detail, i) => (
            <div key={i} className="flex justify-between items-center text-sm">
              <span className="text-subtle font-medium">{detail.label}</span>
              <span className="text-foreground font-bold font-mono text-xs">{detail.value}</span>
            </div>
          ))}

          {fee && (
            <div className="flex justify-between items-center text-sm">
              <span className="text-subtle font-medium">{fee.label ?? "Estimated Fee"}</span>
              <span className={`font-bold ${isHighFee ? "text-red-400" : "text-muted"}`}>
                {fee.value} {fee.asset}
                {feePercentage !== undefined ? ` (${feePercentage.toFixed(1)}%)` : ""}
              </span>
            </div>
          )}

          <div className="flex justify-between items-center text-sm pt-2 border-t border-border">
            <span className="text-subtle font-medium flex items-center gap-1.5">
              <Wallet size={14} /> Network
            </span>
            <span className={`font-bold ${isNetworkMismatch ? "text-red-400" : "text-muted"}`}>
              {network}
            </span>
          </div>

          {expiry && (
            <div className="flex justify-between items-center text-sm">
              <span className="text-subtle font-medium flex items-center gap-1.5">
                <Clock size={14} /> Quote Expiry
              </span>
              <span className={`font-bold ${isExpired ? "text-red-400" : "text-emerald-400"}`}>
                {isExpired ? "Expired" : "Valid"}
              </span>
            </div>
          )}
        </div>
      </div>

      {(isNetworkMismatch || isExpired || isHighFee) && (
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
            {isHighFee && (
              <li>The fee is above the safe threshold. Confirm the route and source asset before approving.</li>
            )}
          </ul>
        </div>
      )}

      {!isNetworkMismatch && !isExpired && !isHighFee && (
        <p className="text-[10px] text-subtle text-center px-4 leading-relaxed italic">
          Verify the details above match your intention. This summary is generated from the exact payload that will be sent to your wallet.
        </p>
      )}
    </div>
  );
}
