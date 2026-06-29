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
  receiptHash?: string | null;
  contractId?: string | null;
  network?: string | null;
  correlationId?: string | null;
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
      {/* Status Timeline */}
      <div className="flex items-center justify-center gap-2 mb-4 text-sm font-medium">
        <div className="flex flex-col items-center">
          <div className="w-8 h-8 rounded-full bg-indigo-500/20 text-indigo-400 flex items-center justify-center mb-2">
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>
          </div>
          <span className="text-muted text-[10px] uppercase tracking-wider">Initiated</span>
        </div>
        <div className="w-12 h-0.5 bg-indigo-500/50 -mt-6"></div>
        <div className="flex flex-col items-center">
          <div className="w-8 h-8 rounded-full bg-indigo-500/20 text-indigo-400 flex items-center justify-center mb-2">
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>
          </div>
          <span className="text-muted text-[10px] uppercase tracking-wider">Pending</span>
        </div>
        <div className="w-12 h-0.5 bg-green-500/50 -mt-6"></div>
        <div className="flex flex-col items-center">
          <div className="w-8 h-8 rounded-full bg-green-500/20 text-green-400 flex items-center justify-center mb-2">
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>
          </div>
          <span className="text-success text-[10px] uppercase tracking-wider font-bold">Success</span>
        </div>
      </div>

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
      <div className="bg-gradient-to-br from-green-500/10 to-indigo-500/10 border border-green-400/30 rounded-2xl p-8">
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
      <div className="bg-green-500/10 border border-green-400/30 rounded-xl p-6">
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
          className="block w-full py-4 bg-indigo-600 hover:bg-indigo-700 rounded-xl font-bold text-lg text-center transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300 focus-visible:ring-offset-2 focus-visible:ring-offset-background"
        >
          Back to Homepage
        </Link>

        {status.transactionHash && (
          <button
            type="button"
            aria-label="Share receipt data for support"
            onClick={() => {
              const debugData = `--- Support Receipt Data ---\nStatus: SUCCESS\nTx Hash: ${status.transactionHash}\nReceipt Hash: ${status.receiptHash || 'N/A'}\nContract: ${status.contractId || 'N/A'}\nNetwork: ${status.network || 'N/A'}\nCorrelation ID: ${status.correlationId || 'N/A'}\nPaid To: @${status.username}\nAmount: ${status.amount} ${status.asset}\nTime: ${status.paidAt || 'N/A'}`;
              navigator.clipboard.writeText(debugData);
            }}
            className="w-full py-3 bg-surface-strong hover:bg-surface-strong rounded-xl font-semibold transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300 focus-visible:ring-offset-2 focus-visible:ring-offset-background flex items-center justify-center gap-2"
          >
            <svg className="w-5 h-5 text-muted" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" /></svg>
            Share Receipt Data
          </button>
        )}
      </div>

      {/* Technical Details for Support */}
      <div className="bg-card/30 border border-border rounded-xl p-4 mt-8">
        <details className="group">
          <summary className="flex cursor-pointer items-center justify-between font-semibold text-muted hover:text-foreground transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300 rounded">
            <span>Technical Details (Support)</span>
            <span className="transition group-open:rotate-180">
              <svg fill="none" height="24" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" viewBox="0 0 24 24" width="24"><polyline points="6 9 12 15 18 9" /></svg>
            </span>
          </summary>
          <div className="mt-4 space-y-2 text-xs font-mono text-muted overflow-x-auto">
            <div className="flex justify-between border-b border-border/50 pb-2">
              <span>Receipt Hash:</span>
              <span className="text-foreground">{status.receiptHash || 'N/A'}</span>
            </div>
            <div className="flex justify-between border-b border-border/50 pb-2">
              <span>Contract ID:</span>
              <span className="text-foreground">{status.contractId || 'N/A'}</span>
            </div>
            <div className="flex justify-between border-b border-border/50 pb-2">
              <span>Network:</span>
              <span className="text-foreground">{status.network || 'N/A'}</span>
            </div>
            <div className="flex justify-between">
              <span>Correlation ID:</span>
              <span className="text-foreground">{status.correlationId || 'N/A'}</span>
            </div>
          </div>
        </details>
      </div>
    </div>
  );
}
