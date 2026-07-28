"use client";

import { useState } from "react";
import { SigningSummary } from "@/components/SigningSummary";
import {
  CheckCircle2,
  Loader2,
  AlertCircle,
  RefreshCw,
  Settings,
  ChevronDown,
  ChevronUp,
  Terminal,
  WalletCards,
  AlertTriangle
} from "lucide-react";

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

type TransactionStep = "idle" | "simulate" | "sign" | "submit" | "completed";
type StepStatus = "pending" | "processing" | "success" | "error";
type SimulatorOutcome = "success" | "fail_simulate" | "fail_sign" | "fail_submit";

export function ActivePaymentState({
  status,
  onPaymentInitiated,
  onPaymentCompleted,
}: ActivePaymentStateProps) {
  const [selectedSourceAsset, setSelectedSourceAsset] = useState<string | null>(null);
  const [copyStatus, setCopyStatus] = useState<string | null>(null);
  const [showPreview, setShowPreview] = useState(false);

  // Stepper state
  const [txStep, setTxStep] = useState<TransactionStep>("idle");
  const [simulateStatus, setSimulateStatus] = useState<StepStatus>("pending");
  const [signStatus, setSignStatus] = useState<StepStatus>("pending");
  const [submitStatus, setSubmitStatus] = useState<StepStatus>("pending");

  const [errorType, setErrorType] = useState<"contract" | "rejection" | "network" | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [signedPayload, setSignedPayload] = useState<string | null>(null);
  const [logs, setLogs] = useState<string[]>([]);

  // Dev Simulator Settings
  const [simulatorOutcome, setSimulatorOutcome] = useState<SimulatorOutcome>("success");
  const [showDevPanel, setShowDevPanel] = useState(false);

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

  const addLog = (message: string) => {
    const time = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    setLogs((prev) => [...prev, `[${time}] ${message}`]);
  };

  const runPipeline = async (startStep: "simulate" | "sign" | "submit") => {
    setErrorType(null);
    setErrorMessage(null);
    onPaymentInitiated();

    if (startStep === "simulate") {
      setTxStep("simulate");
      setSimulateStatus("processing");
      setSignStatus("pending");
      setSubmitStatus("pending");
      setLogs([]);
      addLog("Starting transaction pipeline execution...");
      addLog("Validating recipient public key and destination address...");

      await new Promise((r) => setTimeout(r, 1500));

      if (simulatorOutcome === "fail_simulate") {
        setSimulateStatus("error");
        setErrorType("contract");
        const err = "Contract Error: Transaction simulation failed. The smart contract returned an error (e.g. insufficient funds, expired path, or invalid preconditions).";
        setErrorMessage(err);
        addLog("ERROR: Transaction simulation failed (op_underfunded). Recipient balance is insufficient or swap path is invalid.");
        return;
      }

      setSimulateStatus("success");
      addLog("Simulation successful: gas limit checked, swap path verified.");
      startStep = "sign";
    }

    if (startStep === "sign") {
      setTxStep("sign");
      setSignStatus("processing");
      addLog("Requesting transaction signature from Stellar wallet (Freighter/Lobstr)...");

      await new Promise((r) => setTimeout(r, 2000));

      if (simulatorOutcome === "fail_sign") {
        setSignStatus("error");
        setErrorType("rejection");
        const err = "User Rejection: Signature request denied. The transaction was rejected in your wallet.";
        setErrorMessage(err);
        addLog("ERROR: User rejected signature request in wallet extension.");
        return;
      }

      // Simulate generating signed payload (XDR)
      const mockXdr = "AAAAA" + Math.random().toString(36).substring(7).toUpperCase() + "xdrSignedPayload314159265358979323846264";
      setSignedPayload(mockXdr);
      setSignStatus("success");
      addLog(`Transaction signed. Signed XDR envelope generated (${mockXdr.substring(0, 16)}...).`);
      startStep = "submit";
    }

    if (startStep === "submit") {
      setTxStep("submit");
      setSubmitStatus("processing");
      if (signedPayload) {
        addLog(`Idempotency active: broadcasting cached signed XDR (${signedPayload.substring(0, 16)}...)`);
      } else {
        addLog("Broadcasting transaction payload to Stellar Horizon network...");
      }

      await new Promise((r) => setTimeout(r, 2000));

      if (simulatorOutcome === "fail_submit") {
        setSubmitStatus("error");
        setErrorType("network");
        const err = "Network Error: Broadcast timed out or Horizon node was unreachable. You can safely retry without resigning.";
        setErrorMessage(err);
        addLog("ERROR: Connection timeout during broadcast to Horizon node.");
        addLog("SAFE TO RETRY: The signed transaction envelope (XDR) is cached. Retrying will not duplicate payment.");
        return;
      }

      setSubmitStatus("success");
      setTxStep("completed");
      addLog("Transaction confirmed in ledger! Fetching tx hash...");

      // Complete payment
      const txHash = "tx_" + Math.random().toString(36).substring(2, 12) + Math.random().toString(36).substring(2, 12);
      addLog(`Transaction Hash: ${txHash}`);

      await new Promise((r) => setTimeout(r, 1000));
      onPaymentCompleted(txHash);
    }
  };

  const handlePay = async () => {
    if (!showPreview) {
      setShowPreview(true);
      return;
    }
    runPipeline("simulate");
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

  const handleRetryStep = () => {
    if (errorType === "contract") {
      runPipeline("simulate");
    } else if (errorType === "rejection") {
      runPipeline("sign");
    } else if (errorType === "network") {
      runPipeline("submit");
    }
  };

  const handleCancel = () => {
    setTxStep("idle");
    setSimulateStatus("pending");
    setSignStatus("pending");
    setSubmitStatus("pending");
    setErrorType(null);
    setErrorMessage(null);
    setSignedPayload(null);
    setLogs([]);
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

  // ── RENDER TRANSACTION PIPELINE STEPPER UI ─────────────────
  if (txStep !== "idle") {
    return (
      <div className="space-y-6 animate-in fade-in slide-in-from-bottom-2 duration-300">
        {/* Header */}
        <div className="text-center">
          <div className="w-16 h-16 bg-indigo-500/10 rounded-full flex items-center justify-center mx-auto mb-4 border border-indigo-500/20">
            <WalletCards className="w-8 h-8 text-indigo-400" />
          </div>
          <h1 className="text-2xl font-black tracking-tight text-foreground">
            {txStep === "completed" ? "Payment Successful" : "Transaction Execution"}
          </h1>
          <p className="text-subtle text-sm mt-1">
            Simulating, signing, and submitting your Stellar payment
          </p>
        </div>

        {/* Stepper Wizard Card */}
        <div className="bg-card/90 border border-border-strong rounded-3xl p-6 md:p-8 shadow-2xl relative overflow-hidden backdrop-blur-2xl">
          {/* Subtle Glow backdrop */}
          <div className="absolute -right-20 -top-20 w-40 h-40 bg-indigo-500/10 rounded-full blur-3xl pointer-events-none" />

          {/* Stepper Progress Bar */}
          <div className="relative flex items-center justify-between max-w-md mx-auto mb-8">
            {/* Connecting Lines */}
            <div className="absolute top-5 left-0 right-0 h-[2px] bg-surface-strong -translate-y-1/2 z-0" />

            {/* Segment Progress Highlight */}
            <div
              className="absolute top-5 left-0 h-[2px] bg-indigo-500 -translate-y-1/2 z-0 transition-all duration-500"
              style={{
                width: simulateStatus === "success"
                  ? (signStatus === "success" ? "100%" : "50%")
                  : "0%"
              }}
            />

            {/* Step 1: Simulate */}
            <div className="flex flex-col items-center z-10 relative flex-1">
              <div
                className={`w-10 h-10 rounded-full flex items-center justify-center border-2 font-bold transition-all duration-300 ${simulateStatus === "success"
                    ? "bg-success-soft border-emerald-500 text-emerald-400"
                    : simulateStatus === "processing"
                      ? "bg-indigo-500/20 border-indigo-500 text-indigo-400 animate-pulse"
                      : simulateStatus === "error"
                        ? "bg-red-500/20 border-red-500 text-red-400"
                        : "bg-background border-border-strong text-subtle"
                  }`}
              >
                {simulateStatus === "success" ? (
                  <CheckCircle2 className="w-5 h-5" />
                ) : simulateStatus === "processing" ? (
                  <Loader2 className="w-5 h-5 animate-spin" />
                ) : simulateStatus === "error" ? (
                  <AlertCircle className="w-5 h-5" />
                ) : (
                  "1"
                )}
              </div>
              <span className={`text-[11px] font-black uppercase mt-2 tracking-wider ${simulateStatus === "processing" ? "text-indigo-400" : "text-subtle"
                }`}>
                Simulate
              </span>
            </div>

            {/* Step 2: Sign */}
            <div className="flex flex-col items-center z-10 relative flex-1">
              <div
                className={`w-10 h-10 rounded-full flex items-center justify-center border-2 font-bold transition-all duration-300 ${signStatus === "success"
                    ? "bg-success-soft border-emerald-500 text-emerald-400"
                    : signStatus === "processing"
                      ? "bg-indigo-500/20 border-indigo-500 text-indigo-400 animate-pulse"
                      : signStatus === "error"
                        ? "bg-red-500/20 border-red-500 text-red-400"
                        : "bg-background border-border-strong text-subtle"
                  }`}
              >
                {signStatus === "success" ? (
                  <CheckCircle2 className="w-5 h-5" />
                ) : signStatus === "processing" ? (
                  <Loader2 className="w-5 h-5 animate-spin" />
                ) : signStatus === "error" ? (
                  <AlertCircle className="w-5 h-5" />
                ) : (
                  "2"
                )}
              </div>
              <span className={`text-[11px] font-black uppercase mt-2 tracking-wider ${signStatus === "processing" ? "text-indigo-400" : "text-subtle"
                }`}>
                Sign
              </span>
            </div>

            {/* Step 3: Submit */}
            <div className="flex flex-col items-center z-10 relative flex-1">
              <div
                className={`w-10 h-10 rounded-full flex items-center justify-center border-2 font-bold transition-all duration-300 ${submitStatus === "success"
                    ? "bg-success-soft border-emerald-500 text-emerald-400"
                    : submitStatus === "processing"
                      ? "bg-indigo-500/20 border-indigo-500 text-indigo-400 animate-pulse"
                      : submitStatus === "error"
                        ? "bg-red-500/20 border-red-500 text-red-400"
                        : "bg-background border-border-strong text-subtle"
                  }`}
              >
                {submitStatus === "success" ? (
                  <CheckCircle2 className="w-5 h-5" />
                ) : submitStatus === "processing" ? (
                  <Loader2 className="w-5 h-5 animate-spin" />
                ) : submitStatus === "error" ? (
                  <AlertCircle className="w-5 h-5" />
                ) : (
                  "3"
                )}
              </div>
              <span className={`text-[11px] font-black uppercase mt-2 tracking-wider ${submitStatus === "processing" ? "text-indigo-400" : "text-subtle"
                }`}>
                Submit
              </span>
            </div>
          </div>

          {/* Error Callout */}
          {errorMessage && (
            <div className="mb-6 p-4 rounded-2xl bg-red-500/10 border border-red-500/20 animate-in fade-in duration-200">
              <div className="flex gap-3">
                <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
                <div>
                  <h4 className="font-bold text-red-400 text-sm">
                    {errorType === "contract" && "Simulation Contract Failure"}
                    {errorType === "rejection" && "Wallet Signature Request Rejected"}
                    {errorType === "network" && "Horizon Network Timeout"}
                  </h4>
                  <p className="text-xs text-danger/90 mt-1 leading-relaxed">
                    {errorMessage}
                  </p>
                  {errorType === "network" && (
                    <p className="text-[10px] text-indigo-400/90 font-mono mt-2 flex items-center gap-1.5 bg-indigo-500/5 px-2.5 py-1.5 rounded-lg border border-indigo-500/10 w-fit">
                      <span className="w-1.5 h-1.5 rounded-full bg-indigo-400 animate-ping" />
                      Idempotency Active: Retrying will only re-broadcast signed payload.
                    </p>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* Step Detail Status */}
          <div className="text-center py-4 bg-card/[0.02] border border-border rounded-2xl mb-6">
            <p className="text-xs text-subtle uppercase tracking-widest font-black mb-1">
              Current Status
            </p>
            <p className="text-sm font-semibold text-foreground px-6">
              {simulateStatus === "processing" && "Evaluating balance and routing paths..."}
              {simulateStatus === "error" && "Simulation check failed. Adjust options and retry."}
              {signStatus === "processing" && "Awaiting approval in Stellar Wallet extension..."}
              {signStatus === "error" && "Signature request denied. Please retry signing."}
              {submitStatus === "processing" && "Submitting payload to Horizon. Writing to ledger..."}
              {submitStatus === "error" && "Network issue detected. Retry submit safely."}
              {txStep === "completed" && "Transaction completed successfully!"}
            </p>
          </div>

          {/* Terminal Console Logs */}
          <div className="bg-background/90 rounded-2xl border border-border overflow-hidden mb-6 font-mono text-xs shadow-inner">
            <div className="flex items-center justify-between px-4 py-2 border-b border-border bg-background">
              <span className="text-subtle flex items-center gap-2 font-bold text-[10px] uppercase tracking-wider">
                <Terminal size={12} className="text-indigo-400" /> Transaction Console Logs
              </span>
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
            </div>
            <div className="p-4 h-36 overflow-y-auto space-y-1.5 scrollbar-thin scrollbar-thumb-white/15">
              {logs.map((log, i) => (
                <div
                  key={i}
                  className={`leading-relaxed ${log.includes("ERROR:")
                      ? "text-red-400"
                      : log.includes("successful") || log.includes("signed") || log.includes("confirmed")
                        ? "text-emerald-400"
                        : log.includes("SAFE TO RETRY")
                          ? "text-indigo-400 font-bold"
                          : "text-muted"
                    }`}
                >
                  {log}
                </div>
              ))}
              {logs.length === 0 && (
                <div className="text-faint italic">No output yet. Simulation starting...</div>
              )}
            </div>
          </div>

          {/* Control Buttons */}
          <div className="flex gap-4">
            {errorMessage ? (
              <>
                <button
                  type="button"
                  onClick={handleCancel}
                  className="flex-1 py-3.5 bg-surface-strong hover:bg-surface-strong text-muted font-bold rounded-xl transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300"
                >
                  Cancel Payment
                </button>
                <button
                  type="button"
                  onClick={handleRetryStep}
                  className="flex-[2] py-3.5 bg-indigo-600 hover:bg-indigo-700 text-white font-black rounded-xl transition flex items-center justify-center gap-2 shadow-lg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300"
                >
                  <RefreshCw size={16} className="animate-spin-slow" />
                  {errorType === "contract" && "Retry Simulation"}
                  {errorType === "rejection" && "Try Signing Again"}
                  {errorType === "network" && "Retry Broadcast"}
                </button>
              </>
            ) : (
              <button
                type="button"
                disabled={true}
                className="w-full py-4 bg-surface-strong text-subtle font-bold rounded-xl flex items-center justify-center gap-2.5 cursor-not-allowed"
              >
                <Loader2 size={18} className="animate-spin text-indigo-400" />
                Processing Transaction...
              </button>
            )}
          </div>
        </div>

        {/* ── SIMULATOR CONTROL PANEL (DEV TOOL) ────────────────── */}
        <div className="bg-card border border-border rounded-2xl overflow-hidden">
          <button
            type="button"
            onClick={() => setShowDevPanel(!showDevPanel)}
            className="w-full flex items-center justify-between px-5 py-4 hover:bg-card/[0.02] transition-colors"
          >
            <span className="flex items-center gap-2 text-sm font-bold text-subtle">
              <Settings size={16} className="text-indigo-400" /> Stellar Pipeline Simulator Controls
            </span>
            {showDevPanel ? (
              <ChevronUp size={16} className="text-subtle" />
            ) : (
              <ChevronDown size={16} className="text-subtle" />
            )}
          </button>

          {showDevPanel && (
            <div className="px-5 pb-5 pt-2 border-t border-border space-y-4 animate-in fade-in duration-200">
              <p className="text-xs text-subtle leading-normal">
                Toggle the behavior below to simulate and verify different outcomes, network errors, and contract rejections in the transaction stepper.
              </p>

              <div className="grid grid-cols-2 gap-3">
                <button
                  type="button"
                  onClick={() => setSimulatorOutcome("success")}
                  className={`p-3 rounded-xl border text-xs text-left font-semibold transition ${simulatorOutcome === "success"
                      ? "border-emerald-500/50 bg-success-soft text-emerald-400"
                      : "border-border bg-background text-subtle hover:border-brand hover:bg-brand-soft"
                    }`}
                >
                  <p className="font-bold">Always Succeed</p>
                  <p className="text-[10px] text-subtle mt-0.5">Success path through to PaidState</p>
                </button>

                <button
                  type="button"
                  onClick={() => setSimulatorOutcome("fail_simulate")}
                  className={`p-3 rounded-xl border text-xs text-left font-semibold transition ${simulatorOutcome === "fail_simulate"
                      ? "border-red-500/50 bg-red-500/10 text-red-400"
                      : "border-border bg-background text-subtle hover:border-border-strong"
                    }`}
                >
                  <p className="font-bold">Fail on Simulation</p>
                  <p className="text-[10px] text-subtle mt-0.5">Simulate contract / funds error</p>
                </button>

                <button
                  type="button"
                  onClick={() => setSimulatorOutcome("fail_sign")}
                  className={`p-3 rounded-xl border text-xs text-left font-semibold transition ${simulatorOutcome === "fail_sign"
                      ? "border-red-500/50 bg-red-500/10 text-red-400"
                      : "border-border bg-background text-subtle hover:border-border-strong"
                    }`}
                >
                  <p className="font-bold">Fail on Signing</p>
                  <p className="text-[10px] text-subtle mt-0.5">Simulate user rejecting wallet pop-up</p>
                </button>

                <button
                  type="button"
                  onClick={() => setSimulatorOutcome("fail_submit")}
                  className={`p-3 rounded-xl border text-xs text-left font-semibold transition ${simulatorOutcome === "fail_submit"
                      ? "border-red-500/50 bg-red-500/10 text-red-400"
                      : "border-border bg-background text-subtle hover:border-border-strong"
                    }`}
                >
                  <p className="font-bold">Fail on Submission</p>
                  <p className="text-[10px] text-subtle mt-0.5">Simulate Horizon network broadcast timeout</p>
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    );
  }

  // ── RENDER DEFAULT IDLE STATE (PAYMENT REQUEST DETAILS) ───
  return (
    <div className="space-y-8 animate-in fade-in duration-300">
      <div className="text-center">
        <div
          aria-hidden="true"
          className="w-20 h-20 bg-success-soft rounded-full flex items-center justify-center mx-auto mb-6"
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
        <p className="text-muted">{status.userMessage}</p>
      </div>

      <div className="bg-card border border-border-strong rounded-2xl p-8">
        <h2 className="text-xl font-bold mb-6">Payment Details</h2>

        <dl className="space-y-4">
          <div className="flex justify-between items-center py-3 border-b border-border">
            <dt className="text-muted">Recipient</dt>
            <dd className="font-semibold">@{status.username}</dd>
          </div>

          <div className="flex justify-between items-center py-3 border-b border-border">
            <dt className="text-muted">Amount</dt>
            <dd className="text-2xl font-bold text-brand">
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
              <dt className="text-muted">Expires</dt>
              <dd className="text-sm">
                {new Date(status.expiresAt).toLocaleDateString()}
              </dd>
            </div>
          )}
        </dl>
      </div>

      {hasSwapOptions && status.acceptsMultipleAssets && (
        <div className="bg-card/50 border border-border-strong rounded-2xl p-8">
          <h2 id="payment-options-heading" className="text-xl font-bold mb-4">
            Payment Options
          </h2>
          <p className="text-sm text-muted mb-6">
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
              className={`w-full p-4 rounded-xl border transition-all text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300 focus-visible:ring-offset-2 focus-visible:ring-offset-background ${selectedSourceAsset === null
                  ? "border-brand bg-brand-soft bg-indigo-500/10"
                  : "border-border hover:border-border-strong"
                }`}
            >
              <div className="flex justify-between items-center">
                <div>
                  <p className="font-semibold">Pay with {status.asset}</p>
                  <p className="text-sm text-muted">Direct payment</p>
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
                className={`w-full p-4 rounded-xl border transition-all text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300 focus-visible:ring-offset-2 focus-visible:ring-offset-background ${selectedSourceAsset === option.sourceAsset
                    ? "border-indigo-500 bg-indigo-500/10"
                    : "border-border hover:border-border-strong"
                  }`}
              >
                <div className="flex justify-between items-center">
                  <div>
                    <p className="font-semibold">
                      Pay with {option.sourceAsset}
                    </p>
                    <p className="text-sm text-muted">
                      {option.rateDescription}
                    </p>
                  </div>
                  <div className="text-right">
                    <p className="font-bold">{option.sourceAmount}</p>
                    <p className="text-xs text-subtle">
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
          aria-label={
            showPreview
              ? `Confirm payment to ${status.username}`
              : `Review payment details for ${status.username}`
          }
          className="w-full py-4 bg-brand hover:opacity-90 rounded-xl font-bold text-lg transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300 focus-visible:ring-offset-2 focus-visible:ring-offset-background"
        >
          {showPreview ? "Open Wallet & Pay" : "Review Payment"}
        </button>

        <button
          type="button"
          onClick={handleCopyLink}
          aria-label="Copy payment link to clipboard"
          className="w-full py-3 bg-card border border-border hover:bg-surface hover:bg-surface-strong rounded-xl font-semibold transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300 focus-visible:ring-offset-2 focus-visible:ring-offset-background"
        >
          Copy Payment Link
        </button>

        <p role="status" aria-live="polite" className="sr-only">
          {copyStatus ?? ""}
        </p>
      </div>

      <div className="bg-brand-soft border border-blue-400/30 rounded-xl p-4">
        <p className="text-sm text-brand">
          <strong>How it works:</strong> Review the transaction summary before your Stellar wallet opens. After confirmation, your wallet will request the signature for this exact payload.
        </p>
      </div>
    </div>
  );
}
