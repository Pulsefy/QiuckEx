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
        <div className="w-20 h-20 bg-purple-500/10 rounded-full flex items-center justify-center mx-auto mb-6">
          <svg
            className="w-10 h-10 text-purple-500"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
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
        <p className="text-neutral-400">{status.userMessage}</p>
      </div>

      {/* Payment Details Card */}
      <div className="bg-neutral-900/50 border border-white/10 rounded-2xl p-8">
        <h2 className="text-xl font-bold mb-6">Refund Details</h2>

        <div className="space-y-4">
          <div className="flex justify-between items-center py-3 border-b border-white/5">
            <span className="text-neutral-400">Original Recipient</span>
            <span className="font-semibold">@{status.username}</span>
          </div>

          <div className="flex justify-between items-center py-3 border-b border-white/5">
            <span className="text-neutral-400">Refunded Amount</span>
            <span className="text-2xl font-bold text-purple-400">
              {status.amount} {status.asset}
            </span>
          </div>

          {status.memo && (
            <div className="flex justify-between items-center py-3 border-b border-white/5">
              <span className="text-neutral-400">Original Memo</span>
              <span className="font-mono text-sm">{status.memo}</span>
            </div>
          )}

          {status.paidAt && (
            <div className="flex justify-between items-center py-3 border-b border-white/5">
              <span className="text-neutral-400">Original Payment Date</span>
              <span className="text-sm">
                {new Date(status.paidAt).toLocaleDateString()}
              </span>
            </div>
          )}
        </div>
      </div>

      {/* Info */}
      <div className="bg-purple-500/10 border border-purple-500/20 rounded-xl p-6">
        <div className="flex gap-4">
          <div className="flex-shrink-0">
            <svg
              className="w-6 h-6 text-purple-500"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
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
            <h3 className="font-semibold text-purple-400 mb-2">
              About this refund
            </h3>
            <p className="text-sm text-purple-400/80">
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
