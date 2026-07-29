"use client";

import Link from "next/link";

interface PaymentLinkStatus {
  username: string;
  amount: string;
  asset: string;
  memo: string | null;
  transactionHash: string | null;
  paidAt: string | null;
  userMessage: string;
}

interface RefundedPaymentStateProps {
  status: PaymentLinkStatus;
}

export function RefundedPaymentState({ status }: RefundedPaymentStateProps) {
  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="text-center">
        <div
          aria-hidden="true"
          className="w-20 h-20 bg-purple-500/10 rounded-full flex items-center justify-center mx-auto mb-6"
        >
          <svg
            className="w-10 h-10 text-purple-400"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
            focusable="false"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M3 10h10a8 8 0 018 8v2M3 10l6 6m-6-6l6-6"
            />
          </svg>
        </div>
        <h1 className="text-3xl font-bold mb-2">Payment Refunded</h1>
        <p className="text-muted">{status.userMessage}</p>
      </div>

      {/* Payment Details Card */}
      <div className="bg-card/50 border border-border-strong rounded-2xl p-8">
        <h2 className="text-xl font-bold mb-6">Refund Details</h2>

        <dl className="space-y-4">
          <div className="flex justify-between items-center py-3 border-b border-border">
            <dt className="text-muted">Original Recipient</dt>
            <dd className="font-semibold">@{status.username}</dd>
          </div>

          <div className="flex justify-between items-center py-3 border-b border-border">
            <dt className="text-muted">Refunded Amount</dt>
            <dd className="text-2xl font-bold text-brand">
              {status.amount} {status.asset}
            </dd>
          </div>

          {status.memo && (
            <div className="flex justify-between items-center py-3 border-b border-border">
              <dt className="text-muted">Original Memo</dt>
              <dd className="font-mono text-sm">{status.memo}</dd>
            </div>
          )}

          {status.paidAt && (
            <div className="flex justify-between items-center py-3 border-b border-border">
              <dt className="text-muted">Original Payment Date</dt>
              <dd className="text-sm">
                {new Date(status.paidAt).toLocaleDateString()}
              </dd>
            </div>
          )}
        </dl>
      </div>

      {/* Info */}
      <div className="bg-purple-500/10 border border-purple-400/30 rounded-xl p-6">
        <div className="flex gap-4">
          <div className="flex-shrink-0" aria-hidden="true">
            <svg
              className="w-6 h-6 text-purple-400"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
              focusable="false"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
              />
            </svg>
          </div>
          <div>
            <h3 className="font-semibold text-brand mb-2">
              About this refund
            </h3>
            <p className="text-sm text-brand/90">
              This payment has been refunded by the recipient. The funds have
              been returned to the original sender&apos;s account. Refunds are
              processed on the Stellar network and may take a few moments to
              appear in your wallet.
            </p>
          </div>
        </div>
      </div>

      {/* Action Buttons */}
      <div className="space-y-4">
        <Link
          href="/"
          className="block w-full py-4 bg-indigo-600 hover:bg-indigo-700 rounded-xl font-bold text-lg text-center transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300 focus-visible:ring-offset-2 focus-visible:ring-offset-background"
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
