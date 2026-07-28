"use client";

import { useEffect, useState } from "react";

export function NetworkBadge() {
  const [network, setNetwork] = useState<string | undefined>(undefined);

  useEffect(() => {
    setNetwork(process.env.NEXT_PUBLIC_STELLAR_NETWORK);
  }, []);

  if (!network) return null;

  const normalized = network.toLowerCase();

  const badgeStyles: Record<string, string> = {
    testnet: "bg-warning-soft text-warning border border-warning-soft",
    futurenet: "bg-brand-soft text-brand border border-brand-soft",
    mainnet: "bg-success-soft text-success border border-success-soft",
  };

  const label = {
    testnet: "TESTNET",
    futurenet: "FUTURENET",
    mainnet: "MAINNET",
  }[normalized] ?? network.toUpperCase();

  return (
    <div
      className={`fixed top-4 left-60 px-3 py-1 rounded-full text-xs font-bold transition-all ${badgeStyles[normalized] || ""}`}
    >
      {label}

      {!process.env.NEXT_PUBLIC_STELLAR_NETWORK && (
        <span className="ml-2 opacity-50 font-normal italic">(default)</span>
      )}
    </div>
  );
}