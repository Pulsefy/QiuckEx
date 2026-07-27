"use client";

import Link from "next/link";

interface ErrorStateProps {
  message: string;
  onRetry: () => void;
  retryCount: number;
}

export function ErrorState({ message, onRetry, retryCount }: ErrorStateProps) {
  const isMultipleFailures = retryCount >= 2;

  return (
    <div
      role="alert"
      aria-live="assertive"
      className="flex flex-col items-center justify-center min-h-[60vh] px-4"
    >
      <div
        aria-hidden="true"
        className="w-20 h-20 bg-red-500/10 rounded-full flex items-center justify-center mb-8"
      >
        <svg
          className="w-10 h-10 text-red-500"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
          focusable="false"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
          />
        </svg>
      </div>

      <h2 className="text-2xl font-bold mb-4">Unable to Load Payment</h2>
      <p className="text-muted text-center max-w-md mb-8">
        <p className="text-subtle text-sm text-center mb-6">
          Check your connection or verify that the payment link is still valid.
        </p>{message}</p>

      {isMultipleFailures && (
        <div className="bg-warning-soft border border-amber-500/20 rounded-xl p-4 mb-8 max-w-md">
          <p className="text-warning text-sm">
            <strong>Multiple failures detected.</strong> This could be due to:
          </p>
          <ul className="text-warning/90 text-sm mt-2 space-y-1 list-disc list-inside">
            <li>Network connectivity issues</li>
            <li>Server temporarily unavailable</li>
            <li>Invalid payment link parameters</li>
          </ul>
        </div>
      )}

      <div className="flex w-full max-w-md flex-col gap-3 sm:flex-row">
        <button
          type="button"
          onClick={onRetry}
          className="px-6 py-3 bg-brand hover:opacity-90 rounded-xl font-semibold transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300 focus-visible:ring-offset-2 focus-visible:ring-offset-background"
        >
          {retryCount === 0 ? "Try Again" : `Retry (Attempt ${retryCount + 1})`}
        </button>

        <Link
          href="/"
          className="px-6 py-3 bg-card border border-border hover:bg-surface rounded-xl font-semibold transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300 focus-visible:ring-offset-2 focus-visible:ring-offset-background"
        >
          Go Home
        </Link>
      </div>

      {retryCount > 0 && (
        <p className="mt-6 text-xs text-muted">
          Still having issues? Contact support with the error message above.
        </p>
      )}
    </div>
  );
}
