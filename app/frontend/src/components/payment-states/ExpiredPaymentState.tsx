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
        <div
          aria-hidden="true"
          className="w-20 h-20 bg-warning-soft rounded-full flex items-center justify-center mx-auto mb-6"
        >
          <svg
            className="w-10 h-10 text-orange-500"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
            focusable="false"
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
        <p className="text-muted">{status.userMessage}</p>
      </div>

      {/* Payment Details Card */}
      <div className="bg-card/50 border border-border-strong rounded-2xl p-8">
        <h2 className="text-xl font-bold mb-6">Original Payment Details</h2>

        <dl className="space-y-4 opacity-80">
          <div className="flex justify-between items-center py-3 border-b border-border">
            <dt className="text-muted">Recipient</dt>
            <dd className="font-semibold">@{status.username}</dd>
          </div>

          <div className="flex justify-between items-center py-3 border-b border-border">
            <dt className="text-muted">Amount</dt>
            <dd className="text-2xl font-bold">
              {status.amount} {status.asset}
            </dd>
          </div>

          {status.memo && (
            <div className="flex justify-between items-center py-3 border-b border-border">
              <dt className="text-muted">Memo</dt>
              <dd className="font-mono text-sm">{status.memo}</dd>
            </div>
          )}

          {status.expiresAt && (
            <div className="flex justify-between items-center py-3 border-b border-border">
              <dt className="text-muted">Expired On</dt>
              <dd className="text-sm">
                {new Date(status.expiresAt).toLocaleDateString()}
              </dd>
            </div>
          )}
        </dl>
      </div>

      {/* Warning */}
      <div className="bg-warning-soft border border-warning/30 rounded-xl p-6">
        <div className="flex gap-4">
          <div className="flex-shrink-0" aria-hidden="true">
            <svg
              className="w-6 h-6 text-orange-400"
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
          <div>
            <h3 className="font-semibold text-warning mb-2">
              Why did this expire?
            </h3>
            <p className="text-sm text-warning/90">
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
          className="block w-full py-4 bg-brand hover:opacity-90 rounded-xl font-bold text-lg text-center transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300 focus-visible:ring-offset-2 focus-visible:ring-offset-background"
        >
          Go to Homepage
        </Link>

        <button
          type="button"
          onClick={() => window.history.back()}
          className="w-full py-3 bg-surface-strong hover:bg-surface-strong rounded-xl font-semibold transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300 focus-visible:ring-offset-2 focus-visible:ring-offset-background"
        >
          Go Back
        </button>
      </div>
    </div>
  );
}
