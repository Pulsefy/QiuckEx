"use client";

import { RouteErrorBoundary } from "@/components/RouteErrorBoundary";

export default function PayError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <RouteErrorBoundary
      routeLabel="Payment"
      supportReference="https://quickex.to/support"
    >
      {/* The reset button in RouteErrorBoundary calls reload as a fallback.
          Next.js error.tsx can pass reset to override: we re-mount via reset(). */}
      <PayErrorInner error={error} reset={reset} />
    </RouteErrorBoundary>
  );
}

/** Inner wrapper so the boundary catches errors in the recovery UI too. */
function PayErrorInner({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <section className="mx-auto flex min-h-[50vh] max-w-2xl flex-col items-center justify-center gap-6 rounded-3xl border border-amber-300/40 bg-background/90 p-8 text-center shadow-2xl shadow-black/20">
      <div className="flex h-16 w-16 items-center justify-center rounded-full bg-amber-400/10">
        <svg
          className="h-8 w-8 text-amber-600 dark:text-amber-400"
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
          strokeWidth={1.5}
          aria-hidden="true"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126ZM12 15.75h.007v.008H12v-.008Z"
          />
        </svg>
      </div>

      <p className="text-sm uppercase tracking-[0.22em] text-subtle">Payment</p>
      <h2 className="text-2xl font-semibold text-foreground">
        Payment page unavailable
      </h2>
      <p className="max-w-md text-sm text-muted">
        We hit an unexpected issue loading this payment page. No payment was
        processed. Please try again or contact support.
      </p>

      <div className="max-w-md rounded-2xl border border-amber-300/30 bg-amber-400/5 px-5 py-4 text-sm text-amber-700 dark:text-amber-400">
        <p className="font-semibold">Need help?</p>
        <p className="mt-1">
          Contact{" "}
          <a
            href="https://quickex.to/support"
            target="_blank"
            rel="noopener noreferrer"
            className="underline underline-offset-2 transition hover:text-amber-900 dark:hover:text-amber-300"
          >
            support@quickex.to
          </a>{" "}
          and quote reference <span className="font-mono">{error.digest ?? "N/A"}</span>.
        </p>
      </div>

      <div className="flex items-center gap-4">
        <button
          type="button"
          onClick={reset}
          className="rounded-xl bg-indigo-500 px-5 py-2.5 text-sm font-semibold text-white shadow-lg transition hover:bg-indigo-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300 focus-visible:ring-offset-2"
        >
          Try again
        </button>
        <a
          href="/"
          className="rounded-xl border border-border bg-surface px-5 py-2.5 text-sm font-semibold text-foreground transition hover:bg-surface-strong focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300 focus-visible:ring-offset-2"
        >
          Go to homepage
        </a>
      </div>
    </section>
  );
}
