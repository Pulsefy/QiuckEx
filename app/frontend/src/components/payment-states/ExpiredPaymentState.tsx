"use client";

import Link from "next/link";

interface PaymentLinkStatus {
  username: string;
  amount: string;
  asset: string;
  memo: string | null;
  expiresAt: string | null;
  userMessage: string;
}

interface ExpiredPaymentStateProps {
  status: PaymentLinkStatus;
}

export function ExpiredPaymentState({ status }: ExpiredPaymentStateProps) {
  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="text-center">
        <div className="w-20 h-20 bg-orange-500/10 rounded-full flex items-center justify-center mx-auto mb-6">
          <svg
            className="w-10 h-10 text-orange-500"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"
            />
          </svg>
        </div>
        <h1 className="text-3xl font-bold mb-2">Link Expired</h1>
        <p className="text-neutral-400">{status.userMessage}</p>
      </div>

      {/* Payment Details Card */}
      <div className="bg-neutral-900/50 border border-white/10 rounded-2xl p-8">
        <h2 className="text-xl font-bold mb-6">Original Payment Details</h2>

        <div className="space-y-4 opacity-60">
          <div className="flex justify-between items-center py-3 border-b border-white/5">
            <span className="text-neutral-400">Recipient</span>
            <span className="font-semibold">@{status.username}</span>
          </div>

          <div className="flex justify-between items-center py-3 border-b border-white/5">
            <span className="text-neutral-400">Amount</span>
            <span className="text-2xl font-bold">
              {status.amount} {status.asset}
            </span>
          </div>

          {status.memo && (
            <div className="flex justify-between items-center py-3 border-b border-white/5">
              <span className="text-neutral-400">Memo</span>
              <span className="font-mono text-sm">{status.memo}</span>
            </div>
          )}

          {status.expiresAt && (
            <div className="flex justify-between items-center py-3 border-b border-white/5">
              <span className="text-neutral-400">Expired On</span>
              <span className="text-sm">
                {new Date(status.expiresAt).toLocaleDateString()}
              </span>
            </div>
          )}
        </div>
      </div>

      {/* Warning */}
      <div className="bg-orange-500/10 border border-orange-500/20 rounded-xl p-6">
        <div className="flex gap-4">
          <div className="flex-shrink-0">
            <svg
              className="w-6 h-6 text-orange-500"
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
          <div>
            <h3 className="font-semibold text-orange-400 mb-2">
              Why did this expire?
            </h3>
            <p className="text-sm text-orange-400/80">
              Payment links have an expiration date for security reasons. This
              link was not used before it expired. Please contact the recipient
              to generate a new payment link.
            </p>
          </div>
        </div>
      </div>

      {/* Action Buttons */}
      <div className="space-y-4">
        <Link
          href="/"
          className="block w-full py-4 bg-indigo-600 hover:bg-indigo-700 rounded-xl font-bold text-lg text-center transition-colors"
        >
          Go to Homepage
        </Link>

        <button
          onClick={() => window.history.back()}
          className="w-full py-3 bg-neutral-800 hover:bg-neutral-700 rounded-xl font-semibold transition-colors"
        >
          Go Back
        </button>
      </div>
    </div>
  );
}
