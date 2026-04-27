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
    <div className="flex flex-col items-center justify-center min-h-[60vh] px-4">
      <div className="w-20 h-20 bg-red-500/10 rounded-full flex items-center justify-center mb-8">
        <svg
          className="w-10 h-10 text-red-500"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
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
      <p className="text-neutral-400 text-center max-w-md mb-8">{message}</p>

      {isMultipleFailures && (
        <div className="bg-amber-500/10 border border-amber-500/20 rounded-xl p-4 mb-8 max-w-md">
          <p className="text-amber-400 text-sm">
            <strong>Multiple failures detected.</strong> This could be due to:
          </p>
          <ul className="text-amber-400/80 text-sm mt-2 space-y-1 list-disc list-inside">
            <li>Network connectivity issues</li>
            <li>Server temporarily unavailable</li>
            <li>Invalid payment link parameters</li>
          </ul>
        </div>
      )}

      <div className="flex gap-4">
        <button
          onClick={onRetry}
          className="px-6 py-3 bg-indigo-600 hover:bg-indigo-700 rounded-xl font-semibold transition-colors"
        >
          {retryCount === 0 ? "Try Again" : `Retry (Attempt ${retryCount + 1})`}
        </button>

        <Link
          href="/"
          className="px-6 py-3 bg-neutral-800 hover:bg-neutral-700 rounded-xl font-semibold transition-colors"
        >
          Go Home
        </Link>
      </div>

      {retryCount > 0 && (
        <p className="mt-6 text-xs text-neutral-600">
          Still having issues? Contact support with the error message above.
        </p>
      )}
    </div>
  );
}
