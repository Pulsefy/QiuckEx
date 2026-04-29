"use client";

import { useEffect, useState, useCallback, Suspense } from "react";
import { useSearchParams } from "next/navigation";
import { NetworkBadge } from "@/components/NetworkBadge";
import { ActivePaymentState } from "@/components/payment-states/ActivePaymentState";
import { ExpiredPaymentState } from "@/components/payment-states/ExpiredPaymentState";
import { PaidPaymentState } from "@/components/payment-states/PaidPaymentState";
import { RefundedPaymentState } from "@/components/payment-states/RefundedPaymentState";
import { LoadingState } from "@/components/payment-states/LoadingState";
import { ErrorState } from "@/components/payment-states/ErrorState";
import { getQuickexApiBase } from "@/lib/api";

type LinkState = "ACTIVE" | "EXPIRED" | "PAID" | "REFUNDED" | "DRAFT";

type PaymentLinkStatus = {
  state: LinkState;
  username: string;
  amount: string;
  asset: string;
  memo: string | null;
  destinationPublicKey: string;
  expiresAt: string | null;
  transactionHash: string | null;
  paidAt: string | null;
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
};

type FetchState = "loading" | "success" | "error";

function PaymentPageContent() {
  const searchParams = useSearchParams();
  const [fetchState, setFetchState] = useState<FetchState>("loading");
  const [status, setStatus] = useState<PaymentLinkStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [retryCount, setRetryCount] = useState(0);

  const username = searchParams.get("username") || "";
  const amount = searchParams.get("amount") || "";
  const asset = searchParams.get("asset") || "XLM";
  const memo = searchParams.get("memo") || undefined;
  const acceptedAssets = searchParams.get("acceptedAssets") || undefined;

  const fetchStatus = useCallback(async () => {
    if (!username || !amount) {
      setFetchState("error");
      setError("Missing required parameters: username and amount");
      return;
    }

    setFetchState("loading");
    setError(null);

    try {
      const apiBase = getQuickexApiBase();
      const params = new URLSearchParams({
        username,
        amount,
        asset,
      });

      if (memo) params.set("memo", memo);
      if (acceptedAssets) params.set("acceptedAssets", acceptedAssets);

      const response = await fetch(
        `${apiBase}/payment-links/status?${params.toString()}`,
        {
          headers: {
            Accept: "application/json",
          },
        },
      );

      if (!response.ok) {
        const errorData = await response.json().catch(() => null);
        throw new Error(
          errorData?.message ||
            `Failed to fetch payment status (${response.status})`,
        );
      }

      const data: PaymentLinkStatus = await response.json();
      setStatus(data);
      setFetchState("success");

      // Track analytics event
      trackAnalyticsEvent("payment_link_viewed", {
        username,
        amount,
        asset,
        state: data.state,
      });
    } catch (err) {
      setFetchState("error");
      setError(err instanceof Error ? err.message : "Unknown error occurred");

      // Track error analytics
      trackAnalyticsEvent("payment_link_error", {
        username,
        amount,
        asset,
        error: err instanceof Error ? err.message : "Unknown error",
      });
    }
  }, [username, amount, asset, memo, acceptedAssets]);

  useEffect(() => {
    fetchStatus();
  }, [fetchStatus]);

  const handleRetry = () => {
    setRetryCount((prev) => prev + 1);
    fetchStatus();

    trackAnalyticsEvent("payment_link_retry", {
      retryCount,
      username,
      amount,
    });
  };

  const handlePaymentInitiated = () => {
    trackAnalyticsEvent("payment_initiated", {
      username,
      amount,
      asset,
      state: status?.state,
    });
  };

  const handlePaymentCompleted = (txHash: string) => {
    trackAnalyticsEvent("payment_completed", {
      username,
      amount,
      asset,
      transactionHash: txHash,
    });
  };

  if (fetchState === "loading") {
    return (
      <div className="min-h-screen bg-black text-white">
        <NetworkBadge />
        <LoadingState />
      </div>
    );
  }

  if (fetchState === "error") {
    return (
      <div className="min-h-screen bg-black text-white">
        <NetworkBadge />
        <ErrorState
          message={error || "Failed to load payment link"}
          onRetry={handleRetry}
          retryCount={retryCount}
        />
      </div>
    );
  }

  if (!status) {
    return (
      <div className="min-h-screen bg-black text-white">
        <NetworkBadge />
        <ErrorState
          message="Payment link data is unavailable"
          onRetry={handleRetry}
          retryCount={retryCount}
        />
      </div>
    );
  }

  const renderStateComponent = () => {
    switch (status.state) {
      case "ACTIVE":
        return (
          <ActivePaymentState
            status={status}
            onPaymentInitiated={handlePaymentInitiated}
            onPaymentCompleted={handlePaymentCompleted}
          />
        );
      case "EXPIRED":
        return <ExpiredPaymentState status={status} />;
      case "PAID":
        return <PaidPaymentState status={status} />;
      case "REFUNDED":
        return <RefundedPaymentState status={status} />;
      default:
        return (
          <ErrorState
            message={`Unknown payment state: ${status.state}`}
            onRetry={handleRetry}
            retryCount={retryCount}
          />
        );
    }
  };

  return (
    <div className="min-h-screen bg-black text-white">
      <NetworkBadge />
      <main className="container mx-auto px-4 py-12 max-w-2xl">
        {renderStateComponent()}
      </main>
    </div>
  );
}

export default function PaymentPage() {
  return (
    <Suspense fallback={<LoadingFallback />}>
      <PaymentPageContent />
    </Suspense>
  );
}

function LoadingFallback() {
  return (
    <div className="min-h-screen bg-black text-white">
      <NetworkBadge />
      <LoadingState />
    </div>
  );
}

// Simple analytics tracking (replace with your analytics provider)
function trackAnalyticsEvent(event: string, data: Record<string, unknown>) {
  if (typeof window !== "undefined") {
    // Replace with your analytics provider (e.g., PostHog, Google Analytics, etc.)
    console.log(`[Analytics] ${event}`, data);

    // Example: window.posthog?.capture(event, data);
    // Example: window.gtag?.('event', event, data);
  }
}
