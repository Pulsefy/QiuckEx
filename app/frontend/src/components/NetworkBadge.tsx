"use client";

import { useEffect, useState } from "react";

export function NetworkBadge() {
  const [network, setNetwork] = useState<string | undefined>(undefined);

  useEffect(() => {
    setNetwork(process.env.NEXT_PUBLIC_STELLAR_NETWORK || "testnet");
  }, []);

  if (network === undefined) return null;

  const isTestnet = network.toLowerCase() === "testnet";

  return (
    <div
      className={`fixed top-4 right-4 px-3 py-1 rounded-full text-xs font-bold transition-all ${
        isTestnet
          ? "bg-yellow-100 text-yellow-800 border border-yellow-200"
          : "bg-green-100 text-green-800 border border-green-200"
      }`}
    >
      {isTestnet ? "TESTNET" : "MAINNET"}
      {!process.env.NEXT_PUBLIC_STELLAR_NETWORK && (
        <span className="ml-2 opacity-50 font-normal italic">(default)</span>
      )}
    </div>
  );
}
