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

interface PaidPaymentStateProps {
  status: PaymentLinkStatus;
}

export function PaidPaymentState({ status }: PaidPaymentStateProps) {
  const explorerUrl = status.transactionHash
    ? `https://stellarchain.io/tx/${status.transactionHash}`
    : null;

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="text-center">
        <div
          aria-hidden="true"
          className="w-24 h-24 bg-green-500/20 rounded-full flex items-center justify-center mx-auto mb-6 animate-pulse motion-reduce:animate-none"
        >
          <svg
            className="w-12 h-12 text-green-400"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
            focusable="false"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={3}
              d="M5 13l4 4L19 7"
            />
          </svg>
        </div>
        <h1 className="text-4xl font-bold mb-3 text-success">
          Payment Complete!
        </h1>
        <p className="text-muted text-lg">{status.userMessage}</p>
      </div>

      {/* Payment Success Card */}
      <div className="bg-gradient-to-br from-green-500/10 to-indigo-500/10 border border-success/30 rounded-2xl p-8">
        <h2 className="text-xl font-bold mb-6">Payment Summary</h2>

        <dl className="space-y-4">
          <div className="flex justify-between items-center py-3 border-b border-border">
            <dt className="text-muted">Paid To</dt>
            <dd className="font-semibold">@{status.username}</dd>
          </div>

          <div className="flex justify-between items-center py-3 border-b border-border">
            <dt className="text-muted">Amount Paid</dt>
            <dd className="text-3xl font-bold text-success">
              {status.amount} {status.asset}
            </dd>
          </div>

          {status.memo && (
            <div className="flex justify-between items-center py-3 border-b border-border">
              <dt className="text-muted">Memo</dt>
              <dd className="font-mono text-sm">{status.memo}</dd>
            </div>
          )}

          {status.paidAt && (
            <div className="flex justify-between items-center py-3 border-b border-border">
              <dt className="text-muted">Completed At</dt>
              <dd className="text-sm">
                {new Date(status.paidAt).toLocaleString()}
              </dd>
            </div>
          )}
        </dl>
      </div>

      {/* Transaction Hash */}
      {status.transactionHash && (
        <div className="bg-card/50 border border-border-strong rounded-2xl p-6">
          <h3 className="text-sm font-semibold text-muted mb-3">
            Transaction Hash
          </h3>
          <div className="bg-background/50 rounded-xl p-4 font-mono text-xs break-all">
            {status.transactionHash}
          </div>

          {explorerUrl && (
            <a
              href={explorerUrl}
              target="_blank"
              rel="noopener noreferrer"
              aria-label="View transaction on Stellar explorer (opens in new tab)"
              className="mt-4 inline-flex items-center gap-2 text-brand hover:text-brand underline-offset-4 hover:underline transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300 focus-visible:ring-offset-2 focus-visible:ring-offset-background rounded"
            >
              <span>View on Explorer</span>
              <svg
                aria-hidden="true"
                focusable="false"
                className="w-4 h-4"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0 0L10 14"
                />
              </svg>
            </a>
          )}
        </div>
      )}

      {/* Success Message */}
      <div className="bg-success-soft border border-green-400/30 rounded-xl p-6">
        <div className="flex gap-4">
          <div className="flex-shrink-0" aria-hidden="true">
            <svg
              className="w-6 h-6 text-green-400"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
              focusable="false"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"
              />
            </svg>
          </div>
          <div>
            <h3 className="font-semibold text-success mb-2">
              What&apos;s next?
            </h3>
            <p className="text-sm text-success/90">
              Your payment has been confirmed on the Stellar network. The
              recipient has been notified and the funds are now available in
              their account.
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
          Back to Homepage
        </Link>

        {status.transactionHash && (
          <button
            type="button"
            aria-label="Copy transaction hash to clipboard"
            onClick={() => {
              navigator.clipboard.writeText(status.transactionHash!);
            }}
            className="w-full py-3 bg-card border border-border hover:bg-surface hover:bg-surface-strong rounded-xl font-semibold transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300 focus-visible:ring-offset-2 focus-visible:ring-offset-background"
          >
            Copy Transaction Hash
          </button>
        )}
      </div>
    </div>
  );
}
