"use client";

import { useState } from "react";

interface PaymentLinkStatus {
  username: string;
  amount: string;
  asset: string;
  memo: string | null;
  destinationPublicKey: string;
  expiresAt: string | null;
  swapOptions?: Array<{
    sourceAmount: string;
    sourceAsset: string;
    destinationAmount: string;
    destinationAsset: string;
    hopCount: number;
    pathHops: string[];
    rateDescription: string;
  }> | null;
  acceptsMultipleAssets: boolean;
  acceptedAssets: string[] | null;
  userMessage: string;
  availableActions: string[];
}

interface ActivePaymentStateProps {
  status: PaymentLinkStatus;
  onPaymentInitiated: () => void;
  onPaymentCompleted: (txHash: string) => void;
}

export function ActivePaymentState({
  status,
  onPaymentInitiated,
  onPaymentCompleted,
}: ActivePaymentStateProps) {
  const [isProcessing, setIsProcessing] = useState(false);
  const [selectedSourceAsset, setSelectedSourceAsset] = useState<string | null>(
    null,
  );

  const handlePay = async () => {
    setIsProcessing(true);
    onPaymentInitiated();

    try {
      // Construct Stellar payment URI
      const uri = constructPaymentURI(status, selectedSourceAsset);

      // Try to open Stellar wallet
      window.location.href = uri;

      // For demo purposes, simulate completion
      // In production, you'd poll for payment confirmation
      setTimeout(() => {
        onPaymentCompleted("pending_confirmation");
      }, 2000);
    } catch (error) {
      console.error("Payment initiation failed:", error);
    } finally {
      setIsProcessing(false);
    }
  };

  const handleCopyLink = () => {
    const url = window.location.href;
    navigator.clipboard.writeText(url);
  };

  const hasSwapOptions = status.swapOptions && status.swapOptions.length > 0;

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="text-center">
        <div className="w-20 h-20 bg-green-500/10 rounded-full flex items-center justify-center mx-auto mb-6">
          <svg
            className="w-10 h-10 text-green-500"
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
        <h1 className="text-3xl font-bold mb-2">Payment Request</h1>
        <p className="text-neutral-400">{status.userMessage}</p>
      </div>

      {/* Payment Details Card */}
      <div className="bg-neutral-900/50 border border-white/10 rounded-2xl p-8">
        <h2 className="text-xl font-bold mb-6">Payment Details</h2>

        <div className="space-y-4">
          <div className="flex justify-between items-center py-3 border-b border-white/5">
            <span className="text-neutral-400">Recipient</span>
            <span className="font-semibold">@{status.username}</span>
          </div>

          <div className="flex justify-between items-center py-3 border-b border-white/5">
            <span className="text-neutral-400">Amount</span>
            <span className="text-2xl font-bold text-indigo-400">
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
              <span className="text-neutral-400">Expires</span>
              <span className="text-sm">
                {new Date(status.expiresAt).toLocaleDateString()}
              </span>
            </div>
          )}
        </div>
      </div>

      {/* Swap Options (if available) */}
      {hasSwapOptions && status.acceptsMultipleAssets && (
        <div className="bg-neutral-900/50 border border-white/10 rounded-2xl p-8">
          <h2 className="text-xl font-bold mb-4">Payment Options</h2>
          <p className="text-sm text-neutral-400 mb-6">
            You can pay with any of these assets:
          </p>

          <div className="space-y-3">
            {/* Direct payment option */}
            <button
              onClick={() => setSelectedSourceAsset(null)}
              className={`w-full p-4 rounded-xl border transition-all ${
                selectedSourceAsset === null
                  ? "border-indigo-500 bg-indigo-500/10"
                  : "border-white/10 hover:border-white/20"
              }`}
            >
              <div className="flex justify-between items-center">
                <div>
                  <p className="font-semibold">Pay with {status.asset}</p>
                  <p className="text-sm text-neutral-400">Direct payment</p>
                </div>
                <p className="font-bold">
                  {status.amount} {status.asset}
                </p>
              </div>
            </button>

            {/* Swap options */}
            {status.swapOptions?.map((option, index) => (
              <button
                key={index}
                onClick={() => setSelectedSourceAsset(option.sourceAsset)}
                className={`w-full p-4 rounded-xl border transition-all ${
                  selectedSourceAsset === option.sourceAsset
                    ? "border-indigo-500 bg-indigo-500/10"
                    : "border-white/10 hover:border-white/20"
                }`}
              >
                <div className="flex justify-between items-center">
                  <div>
                    <p className="font-semibold">
                      Pay with {option.sourceAsset}
                    </p>
                    <p className="text-sm text-neutral-400">
                      {option.rateDescription}
                    </p>
                  </div>
                  <div className="text-right">
                    <p className="font-bold">{option.sourceAmount}</p>
                    <p className="text-xs text-neutral-500">
                      {option.hopCount} hop(s)
                    </p>
                  </div>
                </div>
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Action Buttons */}
      <div className="space-y-4">
        <button
          onClick={handlePay}
          disabled={isProcessing}
          className="w-full py-4 bg-indigo-600 hover:bg-indigo-700 disabled:bg-neutral-700 disabled:cursor-not-allowed rounded-xl font-bold text-lg transition-colors"
        >
          {isProcessing ? "Opening Wallet..." : "Pay Now"}
        </button>

        <button
          onClick={handleCopyLink}
          className="w-full py-3 bg-neutral-800 hover:bg-neutral-700 rounded-xl font-semibold transition-colors"
        >
          Copy Payment Link
        </button>
      </div>

      {/* Info */}
      <div className="bg-blue-500/10 border border-blue-500/20 rounded-xl p-4">
        <p className="text-sm text-blue-400">
          <strong>How it works:</strong> Clicking &quot;Pay Now&quot; will open
          your Stellar wallet. Review and sign the transaction to complete the
          payment.
        </p>
      </div>
    </div>
  );
}

function constructPaymentURI(
  status: PaymentLinkStatus,
  sourceAsset: string | null,
): string {
  const params = new URLSearchParams({
    destination: status.destinationPublicKey,
    amount: status.amount,
  });

  if (status.asset !== "XLM") {
    params.set("asset_code", status.asset);
  }

  if (status.memo) {
    params.set("memo", status.memo);
    params.set("memo_type", "text");
  }

  if (sourceAsset && sourceAsset !== status.asset) {
    // Path payment
    params.set("send_asset", sourceAsset);
  }

  return `web+stellar:pay?${params.toString()}`;
}
