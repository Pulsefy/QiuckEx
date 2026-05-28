"use client";

import { useState } from "react";
import { SigningSummary } from "@/components/SigningSummary";

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
  const [copyStatus, setCopyStatus] = useState<string | null>(null);
  const [showPreview, setShowPreview] = useState(false);

  const selectedSwapOption = status.swapOptions?.find(
    (option) => option.sourceAsset === selectedSourceAsset,
  );

  const feeValue = selectedSwapOption
    ? Math.max(
        0,
        parseFloat(selectedSwapOption.sourceAmount) - parseFloat(status.amount),
      )
    : 0;

  const feePercentage = selectedSwapOption
    ? parseFloat(status.amount) > 0
      ? (feeValue / parseFloat(status.amount)) * 100
      : 0
    : undefined;

  const networkLabel =
    process.env.NEXT_PUBLIC_STELLAR_NETWORK === "mainnet"
      ? "Stellar Mainnet"
      : "Stellar Testnet";

  const handlePay = async () => {
    if (!showPreview) {
      setShowPreview(true);
      return;
    }

    setIsProcessing(true);
    onPaymentInitiated();

    try {
      const uri = constructPaymentURI(status, selectedSourceAsset);
      window.location.href = uri;
      setTimeout(() => {
        onPaymentCompleted("pending_confirmation");
      }, 2000);
    } catch (error) {
      console.error("Payment initiation failed:", error);
    } finally {
      setIsProcessing(false);
    }
  };

  const handleCopyLink = async () => {
    const url = window.location.href;
    try {
      await navigator.clipboard.writeText(url);
      setCopyStatus("Payment link copied to clipboard");
    } catch {
      setCopyStatus("Could not copy link. Please copy from the address bar.");
    }
    window.setTimeout(() => setCopyStatus(null), 3000);
  };

  const hasSwapOptions = status.swapOptions && status.swapOptions.length > 0;

  const summaryDetails = [
    { label: "Destination", value: status.destinationPublicKey },
    { label: "Recipient", value: `@${status.username}` },
    { label: "Payment Asset", value: `${status.amount} ${status.asset}` },
    { label: "Memo", value: status.memo ?? "None" },
    {
      label: "Expires",
      value: status.expiresAt
        ? new Date(status.expiresAt).toLocaleString()
        : "No expiry",
    },
  ];

  if (selectedSourceAsset && selectedSourceAsset !== status.asset) {
    summaryDetails.push({
      label: "Source Asset",
      value: selectedSourceAsset,
    });
    summaryDetails.push({
      label: "Estimated Send",
      value: `${selectedSwapOption?.sourceAmount ?? "?"} ${selectedSourceAsset}`,
    });
  }

  return (
    <div className="space-y-8">
      <div className="text-center">
        <div
          aria-hidden="true"
          className="w-20 h-20 bg-green-500/10 rounded-full flex items-center justify-center mx-auto mb-6"
        >
          <svg
            className="w-10 h-10 text-green-500"
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
        <h1 className="text-3xl font-bold mb-2">Payment Request</h1>
        <p className="text-neutral-300">{status.userMessage}</p>
      </div>

      <div className="bg-neutral-900/50 border border-white/10 rounded-2xl p-8">
        <h2 className="text-xl font-bold mb-6">Payment Details</h2>

        <dl className="space-y-4">
          <div className="flex justify-between items-center py-3 border-b border-white/5">
            <dt className="text-neutral-300">Recipient</dt>
            <dd className="font-semibold">@{status.username}</dd>
          </div>

          <div className="flex justify-between items-center py-3 border-b border-white/5">
            <dt className="text-neutral-300">Amount</dt>
            <dd className="text-2xl font-bold text-indigo-300">
              {status.amount} {status.asset}
            </dd>
          </div>

          {status.memo && (
            <div className="flex justify-between items-center py-3 border-b border-white/5">
              <dt className="text-neutral-300">Memo</dt>
              <dd className="font-mono text-sm">{status.memo}</dd>
            </div>
          )}

          {status.expiresAt && (
            <div className="flex justify-between items-center py-3 border-b border-white/5">
              <dt className="text-neutral-300">Expires</dt>
              <dd className="text-sm">
                {new Date(status.expiresAt).toLocaleDateString()}
              </dd>
            </div>
          )}
        </dl>
      </div>

      {hasSwapOptions && status.acceptsMultipleAssets && (
        <div className="bg-neutral-900/50 border border-white/10 rounded-2xl p-8">
          <h2 id="payment-options-heading" className="text-xl font-bold mb-4">
            Payment Options
          </h2>
          <p className="text-sm text-neutral-300 mb-6">
            You can pay with any of these assets:
          </p>

          <div
            role="radiogroup"
            aria-labelledby="payment-options-heading"
            className="space-y-3"
          >
            <button
              type="button"
              role="radio"
              aria-checked={selectedSourceAsset === null}
              onClick={() => setSelectedSourceAsset(null)}
              className={`w-full p-4 rounded-xl border transition-all text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300 focus-visible:ring-offset-2 focus-visible:ring-offset-black ${
                selectedSourceAsset === null
                  ? "border-indigo-500 bg-indigo-500/10"
                  : "border-white/10 hover:border-white/20"
              }`}
            >
              <div className="flex justify-between items-center">
                <div>
                  <p className="font-semibold">Pay with {status.asset}</p>
                  <p className="text-sm text-neutral-300">Direct payment</p>
                </div>
                <p className="font-bold">
                  {status.amount} {status.asset}
                </p>
              </div>
            </button>

            {status.swapOptions?.map((option, index) => (
              <button
                key={index}
                type="button"
                role="radio"
                aria-checked={selectedSourceAsset === option.sourceAsset}
                aria-label={`Pay with ${option.sourceAmount} ${option.sourceAsset}, ${option.hopCount} hops, ${option.rateDescription}`}
                onClick={() => setSelectedSourceAsset(option.sourceAsset)}
                className={`w-full p-4 rounded-xl border transition-all text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300 focus-visible:ring-offset-2 focus-visible:ring-offset-black ${
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
                    <p className="text-sm text-neutral-300">
                      {option.rateDescription}
                    </p>
                  </div>
                  <div className="text-right">
                    <p className="font-bold">{option.sourceAmount}</p>
                    <p className="text-xs text-neutral-400">
                      {option.hopCount} hop(s)
                    </p>
                  </div>
                </div>
              </button>
            ))}
          </div>
        </div>
      )}

      {showPreview && (
        <div className="mb-6">
          <SigningSummary
            action="purchase"
            amount={{ value: parseFloat(status.amount), asset: status.asset }}
            details={summaryDetails}
            expiry={status.expiresAt ? new Date(status.expiresAt) : undefined}
            network={networkLabel}
            targetNetwork={networkLabel}
            fee={
              selectedSwapOption
                ? {
                    value: feeValue,
                    asset: selectedSwapOption.sourceAsset,
                    label: "Estimated Path Cost",
                    percentage: feePercentage,
                    thresholdPercent: 3,
                    isHigh: feePercentage !== undefined && feePercentage >= 3,
                  }
                : undefined
            }
          />
        </div>
      )}

      <div className="space-y-4">
        <button
          type="button"
          onClick={handlePay}
          disabled={isProcessing}
          aria-label={
            isProcessing
              ? "Opening wallet"
              : showPreview
              ? `Confirm payment to ${status.username}`
              : `Review payment details for ${status.username}`
          }
          aria-busy={isProcessing}
          className="w-full py-4 bg-indigo-600 hover:bg-indigo-700 disabled:bg-neutral-700 disabled:cursor-not-allowed rounded-xl font-bold text-lg transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300 focus-visible:ring-offset-2 focus-visible:ring-offset-black"
        >
          {isProcessing ? "Opening Wallet..." : showPreview ? "Open Wallet" : "Review Payment"}
        </button>

        <button
          type="button"
          onClick={handleCopyLink}
          aria-label="Copy payment link to clipboard"
          className="w-full py-3 bg-neutral-800 hover:bg-neutral-700 rounded-xl font-semibold transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300 focus-visible:ring-offset-2 focus-visible:ring-offset-black"
        >
          Copy Payment Link
        </button>

        <p role="status" aria-live="polite" className="sr-only">
          {copyStatus ?? ""}
        </p>
      </div>

      <div className="bg-blue-500/10 border border-blue-400/30 rounded-xl p-4">
        <p className="text-sm text-blue-200">
          <strong>How it works:</strong> Review the transaction summary before your Stellar wallet opens. After confirmation, your wallet will request the signature for this exact payload.
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
    params.set("send_asset", sourceAsset);
  }

  return `web+stellar:pay?${params.toString()}`;
}
