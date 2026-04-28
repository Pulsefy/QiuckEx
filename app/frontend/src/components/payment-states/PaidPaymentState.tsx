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
        <div className="w-24 h-24 bg-green-500/20 rounded-full flex items-center justify-center mx-auto mb-6 animate-pulse">
          <svg
            className="w-12 h-12 text-green-500"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={3}
              d="M5 13l4 4L19 7"
            />
          </svg>
        </div>
        <h1 className="text-4xl font-bold mb-3 text-green-400">
          Payment Complete!
        </h1>
        <p className="text-neutral-400 text-lg">{status.userMessage}</p>
      </div>

      {/* Payment Success Card */}
      <div className="bg-gradient-to-br from-green-500/10 to-indigo-500/10 border border-green-500/20 rounded-2xl p-8">
        <h2 className="text-xl font-bold mb-6">Payment Summary</h2>

        <div className="space-y-4">
          <div className="flex justify-between items-center py-3 border-b border-white/5">
            <span className="text-neutral-400">Paid To</span>
            <span className="font-semibold">@{status.username}</span>
          </div>

          <div className="flex justify-between items-center py-3 border-b border-white/5">
            <span className="text-neutral-400">Amount Paid</span>
            <span className="text-3xl font-bold text-green-400">
              {status.amount} {status.asset}
            </span>
          </div>

          {status.memo && (
            <div className="flex justify-between items-center py-3 border-b border-white/5">
              <span className="text-neutral-400">Memo</span>
              <span className="font-mono text-sm">{status.memo}</span>
            </div>
          )}

          {status.paidAt && (
            <div className="flex justify-between items-center py-3 border-b border-white/5">
              <span className="text-neutral-400">Completed At</span>
              <span className="text-sm">
                {new Date(status.paidAt).toLocaleString()}
              </span>
            </div>
          )}
        </div>
      </div>

      {/* Transaction Hash */}
      {status.transactionHash && (
        <div className="bg-neutral-900/50 border border-white/10 rounded-2xl p-6">
          <h3 className="text-sm font-semibold text-neutral-400 mb-3">
            Transaction Hash
          </h3>
          <div className="bg-black/50 rounded-xl p-4 font-mono text-xs break-all">
            {status.transactionHash}
          </div>

          {explorerUrl && (
            <a
              href={explorerUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="mt-4 inline-flex items-center gap-2 text-indigo-400 hover:text-indigo-300 transition-colors"
            >
              <span>View on Explorer</span>
              <svg
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
      <div className="bg-green-500/10 border border-green-500/20 rounded-xl p-6">
        <div className="flex gap-4">
          <div className="flex-shrink-0">
            <svg
              className="w-6 h-6 text-green-500"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
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
            <h3 className="font-semibold text-green-400 mb-2">
              What&apos;s next?
            </h3>
            <p className="text-sm text-green-400/80">
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
          className="block w-full py-4 bg-indigo-600 hover:bg-indigo-700 rounded-xl font-bold text-lg text-center transition-colors"
        >
          Back to Homepage
        </Link>

        {status.transactionHash && (
          <button
            onClick={() => {
              navigator.clipboard.writeText(status.transactionHash!);
            }}
            className="w-full py-3 bg-neutral-800 hover:bg-neutral-700 rounded-xl font-semibold transition-colors"
          >
            Copy Transaction Hash
          </button>
        )}
      </div>
    </div>
  );
}
