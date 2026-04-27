import * as React from "react";

export default function MarketplaceLoading() {
  return (
    <div className="min-h-screen text-white selection:bg-indigo-500/30">
      <div className="space-y-10">
        <div className="h-8 w-1/3 rounded-full bg-white/5 animate-pulse" />
        <div className="h-72 rounded-3xl bg-white/5 border border-white/5 animate-pulse" />
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
          {Array.from({ length: 6 }).map((_, idx) => (
            <div
              key={idx}
              className="h-72 rounded-3xl bg-white/5 border border-white/5 animate-pulse"
            />
          ))}
        </div>
      </div>
    </div>
  );
}
