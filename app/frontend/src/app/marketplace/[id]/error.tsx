"use client";

import { RouteErrorBoundary } from "@/components/RouteErrorBoundary";

export default function MarketplaceItemError({
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <RouteErrorBoundary routeLabel="Listing">
      <MarketplaceItemErrorInner reset={reset} />
    </RouteErrorBoundary>
  );
}

function MarketplaceItemErrorInner({ reset }: { reset: () => void }) {
  return (
    <div className="mx-auto flex min-h-[50vh] max-w-2xl flex-col items-center justify-center gap-6 rounded-3xl border border-border-strong bg-background/90 p-8 text-center shadow-2xl shadow-black/20">
      <h2 className="text-2xl font-semibold text-foreground">
        Listing unavailable
      </h2>
      <p className="max-w-md text-sm text-muted">
        We couldn&apos;t load this listing. Please try again or go back to the
        marketplace.
      </p>
      <div className="flex items-center gap-4">
        <button
          type="button"
          onClick={reset}
          className="rounded-xl bg-indigo-500 px-5 py-2.5 text-sm font-semibold text-white shadow-lg transition hover:bg-indigo-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300 focus-visible:ring-offset-2"
        >
          Try again
        </button>
        <a
          href="/marketplace"
          className="rounded-xl border border-border bg-surface px-5 py-2.5 text-sm font-semibold text-foreground transition hover:bg-surface-strong focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300 focus-visible:ring-offset-2"
        >
          Back to marketplace
        </a>
      </div>
    </div>
  );
}
