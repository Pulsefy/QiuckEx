"use client";

export function StagingBanner() {
  const isStaging = process.env.NEXT_PUBLIC_STELLAR_NETWORK !== "mainnet";

  if (!isStaging) return null;

  return (
    <div className="w-full bg-amber-500 text-black text-center py-2 text-sm font-medium">
      ⚠️ This is the STAGING environment for testing purposes only. Do not use real funds.
    </div>
  );
}
