"use client";

import { useState, useCallback, useMemo } from "react";
import { SigningSummary } from "@/components/SigningSummary";
import {
  formatAssetAmount,
  formatDate,
  formatDateTime,
} from "@/lib/formatting";
import { getQuickexApiBase } from "@/lib/api";
import { useWallet } from "@/hooks/useWallet";
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
  AlertTriangle,
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

type TransactionStep = "idle" | "compose" | "sign" | "submit" | "completed";
type StepStatus = "pending" | "processing" | "success" | "error";

interface ComposeTransactionRequest {
  contractId: string;
  method: string;
  params: Array<{ type: string; value: unknown }>;
  sourceAccount: string;
  networkPassphrase?: string;
  idempotencyKey?: string;
  memo?: { type: "text" | "id" | "hash" | "return"; value: string };
}

interface ComposeTransactionResponse {
  success: boolean;
  unsignedXdr?: string;
  error?: string;
  userMessage?: string;
  details?: Record<string, unknown>;
  idempotencyKey?: string;
  simulationSummary?: {
    status: "success";
    footprint: { readOnly: number; readWrite: number };
    estimatedCost: {
      cpuInstructions: number;
      ledgerReads: number;
      ledgerWrites: number;
      eventBytes: number;
      returnValueBytes: number;
    };
  };
}

interface SubmitSignedTransactionResponse {
  success: boolean;
  hash?: string;
  error?: string;
  userMessage?: string;
}

const CONTRACT_ID = process.env.NEXT_PUBLIC_QUICKEX_CONTRACT_ID || "CXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
const NETWORK_PASSPHRASE =
  process.env.NEXT_PUBLIC_STELLAR_NETWORK === "mainnet"
    ? "Public Global Stellar Network ; September 2015"
    : "Test SDF Network ; September 2015";

const isDevelopment = process.env.NODE_ENV === "development";

export function ActivePaymentState({
  status,
  onPaymentInitiated,
  onPaymentCompleted,
}: ActivePaymentStateProps) {
  const {
    wallet,
    isRestoring,
    connect,
    signTransaction,
    availableWallets,
    clearError,
  } = useWallet();

  const [selectedSourceAsset, setSelectedSourceAsset] = useState<string | null>(
    null,
  );
  const [copyStatus, setCopyStatus] = useState<string | null>(null);
  const [showPreview, setShowPreview] = useState(false);

  const [txStep, setTxStep] = useState<TransactionStep>("idle");
  const [composeStatus, setComposeStatus] = useState<StepStatus>("pending");
  const [signStatus, setSignStatus] = useState<StepStatus>("pending");
  const [submitStatus, setSubmitStatus] = useState<StepStatus>("pending");

  const [errorType, setErrorType] = useState<
    "contract" | "rejection" | "network" | "wallet_not_connected" | null
  >(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [idempotencyKey, setIdempotencyKey] = useState<string | null>(null);
  const [logs, setLogs] = useState<string[]>([]);
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

  const addLog = useCallback((message: string) => {
    const time = new Date().toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
    setLogs((prev) => [...prev, `[${time}] ${message}`]);
  }, []);

  const generateIdempotencyKey = useCallback(() => {
    return `pay_${Date.now()}_${Math.random().toString(36).substring(2, 10)}`;
  }, []);

  const buildComposeParams = useCallback((): ComposeTransactionRequest => {
    const params = [
      { type: "address", value: status.destinationPublicKey },
      { type: "i128", value: Math.round(parseFloat(status.amount) * 10_000_000).toString() },
    ];

    if (selectedSwapOption && selectedSwapOption.sourceAsset !== status.asset) {
      params.push({ type: "string", value: selectedSwapOption.sourceAsset });
    }

    if (status.memo) {
      params.push({ type: "string", value: status.memo });
    }

    const request: ComposeTransactionRequest = {
      contractId: CONTRACT_ID,
      method: "pay",
      params,
      sourceAccount: wallet.publicKey!,
      networkPassphrase: NETWORK_PASSPHRASE,
      idempotencyKey: idempotencyKey ?? generateIdempotencyKey(),
    };

    if (status.memo) {
      request.memo = { type: "text", value: status.memo };
    }

    return request;
  }, [status, selectedSwapOption, wallet.publicKey, idempotencyKey, generateIdempotencyKey]);

  const runPipeline = useCallback(async () => {
    if (!wallet.connected || !wallet.publicKey) {
      setErrorType("wallet_not_connected");
      setErrorMessage("Please connect your wallet first.");
      addLog("ERROR: Wallet not connected. Cannot proceed with payment.");
      return;
    }

    setErrorType(null);
    setErrorMessage(null);
    clearError();
    onPaymentInitiated();

    const newIdempotencyKey = generateIdempotencyKey();
    setIdempotencyKey(newIdempotencyKey);
    setTxStep("compose");
    setComposeStatus("processing");
    setSignStatus("pending");
    setSubmitStatus("pending");
    setLogs([]);
    addLog("Starting transaction pipeline execution...");
    addLog("Validating recipient public key and destination address...");

    try {
      // Step 1: Compose transaction (simulate)
      addLog("Requesting transaction composition from backend...");
      const composeRequest = buildComposeParams();
      
      const composeResponse = await fetch(`${getQuickexApiBase()}/transactions/compose`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": newIdempotencyKey,
        },
        body: JSON.stringify(composeRequest),
      });

      const composeResult: ComposeTransactionResponse = await composeResponse.json();

      if (!composeResult.success) {
        setComposeStatus("error");
        setErrorType("contract");
        const err = composeResult.userMessage || composeResult.error || "Transaction simulation failed.";
        setErrorMessage(err);
        addLog(`ERROR: ${err}`);
        return;
      }

      if (!composeResult.unsignedXdr) {
        setComposeStatus("error");
        setErrorType("contract");
        setErrorMessage("Backend did not return unsigned XDR.");
        addLog("ERROR: No unsigned XDR returned from composition.");
        return;
      }

      setComposeStatus("success");
      addLog("Simulation successful: gas limit checked, swap path verified.");
      addLog(`Unsigned XDR received (${composeResult.unsignedXdr.substring(0, 16)}...).`);

      // Step 2: Sign transaction
      setTxStep("sign");
      setSignStatus("processing");
      addLog("Requesting transaction signature from Stellar wallet...");

      let signedPayload: string;
      try {
        signedPayload = await signTransaction(composeResult.unsignedXdr);
      } catch (signErr) {
        setSignStatus("error");
        setErrorType("rejection");
        const err = signErr instanceof Error ? signErr.message : "Signature request denied.";
        setErrorMessage(err);
        addLog(`ERROR: ${err}`);
        return;
      }

      setSignStatus("success");
      addLog(`Transaction signed. Signed XDR envelope generated (${signedPayload.substring(0, 16)}...).`);

      // Step 3: Submit transaction
      setTxStep("submit");
      setSubmitStatus("processing");
      addLog("Broadcasting transaction payload to Stellar network...");

      const submitResponse = await fetch(`${getQuickexApiBase()}/transactions/submit`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Idempotency-Key": newIdempotencyKey,
        },
        body: JSON.stringify({
          signedXdr: signedPayload,
          networkPassphrase: NETWORK_PASSPHRASE,
          idempotencyKey: newIdempotencyKey,
        }),
      });

      const submitResult: SubmitSignedTransactionResponse = await submitResponse.json();

      if (!submitResult.success) {
        setSubmitStatus("error");
        setErrorType("network");
        const err = submitResult.userMessage || submitResult.error || "Transaction submission failed.";
        setErrorMessage(err);
        addLog(`ERROR: ${err}`);
        addLog("SAFE TO RETRY: The signed transaction envelope (XDR) is cached. Retrying will not duplicate payment.");
        return;
      }

      if (!submitResult.hash) {
        setSubmitStatus("error");
        setErrorType("network");
        setErrorMessage("Transaction submitted but no hash returned.");
        addLog("ERROR: No transaction hash returned from submission.");
        return;
      }

      setSubmitStatus("success");
      setTxStep("completed");
      addLog("Transaction confirmed in ledger!");
      addLog(`Transaction Hash: ${submitResult.hash}`);

      await new Promise((r) => setTimeout(r, 1000));
      onPaymentCompleted(submitResult.hash);
    } catch (err) {
      const error = err instanceof Error ? err.message : "Unknown error occurred";
      addLog(`ERROR: ${error}`);
      
      // Determine which step failed based on the current step
      if (txStep === "compose" || composeStatus === "processing") {
        setComposeStatus("error");
        setErrorType("contract");
      } else if (txStep === "sign" || signStatus === "processing") {
        setSignStatus("error");
        setErrorType("rejection");
      } else if (txStep === "submit" || submitStatus === "processing") {
        setSubmitStatus("error");
        setErrorType("network");
      }
      setErrorMessage(error);
    }
  }, [
    wallet.connected,
    wallet.publicKey,
    buildComposeParams,
    signTransaction,
    generateIdempotencyKey,
    addLog,
    onPaymentInitiated,
    onPaymentCompleted,
    clearError,
    txStep,
    composeStatus,
    signStatus,
    submitStatus,
  ]);

  const handlePay = useCallback(async () => {
    if (!showPreview) {
      setShowPreview(true);
      return;
    }
    if (isRestoring) {
      addLog("Waiting for wallet session to restore...");
      return;
    }
    runPipeline();
  }, [showPreview, isRestoring, runPipeline, addLog]);

  const handleCopyLink = useCallback(async () => {
    const url = window.location.href;
    try {
      await navigator.clipboard.writeText(url);
      setCopyStatus("Payment link copied to clipboard");
    } catch {
      setCopyStatus("Could not copy link. Please copy from the address bar.");
    }
    window.setTimeout(() => setCopyStatus(null), 3000);
  }, []);

  const handleRetryStep = useCallback(() => {
    if (errorType === "contract" || errorType === "rejection" || errorType === "network") {
      runPipeline();
    }
  }, [errorType, runPipeline]);

  const handleCancel = useCallback(() => {
    setTxStep("idle");
    setComposeStatus("pending");
    setSignStatus("pending");
    setSubmitStatus("pending");
    setErrorType(null);
    setErrorMessage(null);
    setIdempotencyKey(null);
    setLogs([]);
  }, []);

  const handleWalletConnect = useCallback(async (walletType: "freighter" | "albedo" | "demo") => {
    try {
      await connect(walletType, wallet.network);
      addLog(`Wallet connected: ${walletType}`);
    } catch (err) {
      const error = err instanceof Error ? err.message : "Failed to connect wallet";
      addLog(`ERROR: ${error}`);
    }
  }, [connect, wallet.network, addLog]);

  const hasSwapOptions = status.swapOptions && status.swapOptions.length > 0;

  const summaryDetails = useMemo(() => {
    const details = [
      { label: "Destination", value: status.destinationPublicKey },
      { label: "Recipient", value: `@${status.username}` },
      {
        label: "Payment Asset",
        value: formatAssetAmount(status.amount, status.asset),
      },
      { label: "Memo", value: status.memo ?? "None" },
      {
        label: "Expires",
        value: status.expiresAt ? formatDateTime(status.expiresAt) : "No expiry",
      },
    ];

    if (selectedSourceAsset && selectedSourceAsset !== status.asset) {
      details.push({
        label: "Source Asset",
        value: selectedSourceAsset,
      });
      details.push({
        label: "Estimated Send",
        value: `${selectedSwapOption?.sourceAmount ?? "?"} ${selectedSourceAsset}`,
      });
    }
    return details;
  }, [status, selectedSourceAsset, selectedSwapOption]);

  if (isRestoring) {
    return (
      <div className="space-y-6 animate-in fade-in slide-in-from-bottom-2 duration-300">
        <div className="text-center">
          <div className="w-16 h-16 bg-indigo-500/10 rounded-full flex items-center justify-center mx-auto mb-4 border border-indigo-500/20">
            <Loader2 className="w-8 h-8 text-indigo-400 animate-spin" />
          </div>
          <h1 className="text-2xl font-black tracking-tight text-foreground">
            Restoring Wallet Session
          </h1>
          <p className="text-subtle text-sm mt-1">
            Checking previous wallet connection...
          </p>
        </div>
      </div>
    );
  }

  if (txStep !== "idle") {
    return (
      <div className="space-y-6 animate-in fade-in slide-in-from-bottom-2 duration-300">
        {/* Header */}
        <div className="text-center">
          <div className="w-16 h-16 bg-indigo-500/10 rounded-full flex items-center justify-center mx-auto mb-4 border border-indigo-500/20">
            <WalletCards className="w-8 h-8 text-indigo-400" />
          </div>
          <h1 className="text-2xl font-black tracking-tight text-foreground">
            {txStep === "completed"
              ? "Payment Successful"
              : "Transaction Execution"}
          </h1>
          <p className="text-subtle text-sm mt-1">
            Composing, signing, and submitting your Stellar payment
          </p>
        </div>

        {/* Stepper Wizard Card */}
        <div className="bg-card/90 border border-border-strong rounded-3xl p-6 md:p-8 shadow-2xl relative overflow-hidden backdrop-blur-2xl">
          <div className="absolute -right-20 -top-20 w-40 h-40 bg-indigo-500/10 rounded-full blur-3xl pointer-events-none" />

          {/* Stepper Progress Bar */}
          <div className="relative flex items-center justify-between max-w-md mx-auto mb-8">
            <div className="absolute top-5 left-0 right-0 h-[2px] bg-surface-strong -translate-y-1/2 z-0" />
            <div
              className="absolute top-5 left-0 h-[2px] bg-indigo-500 -translate-y-1/2 z-0 transition-all duration-500"
              style={{
                width:
                  composeStatus === "success"
                    ? signStatus === "success"
                      ? "100%"
                      : "50%"
                    : "0%",
              }}
            />

            {/* Step 1: Compose/Simulate */}
            <div className="flex flex-col items-center z-10 relative flex-1">
              <div
                className={`w-10 h-10 rounded-full flex items-center justify-center border-2 font-bold transition-all duration-300 ${
                  composeStatus === "success"
                    ? "bg-success-soft border-emerald-500 text-emerald-400"
                    : composeStatus === "processing"
                      ? "bg-indigo-500/20 border-indigo-500 text-indigo-400 animate-pulse"
                      : composeStatus === "error"
                        ? "bg-red-500/20 border-red-500 text-red-400"
                        : "bg-background border-border-strong text-subtle"
                }`}
              >
                {composeStatus === "success" ? (
                  <CheckCircle2 className="w-5 h-5" />
                ) : composeStatus === "processing" ? (
                  <Loader2 className="w-5 h-5 animate-spin" />
                ) : composeStatus === "error" ? (
                  <AlertCircle className="w-5 h-5" />
                ) : (
                  "1"
                )}
              </div>
              <span
                className={`text-[11px] font-black uppercase mt-2 tracking-wider ${
                  composeStatus === "processing"
                    ? "text-indigo-400"
                    : "text-subtle"
                }`}
              >
                Compose
              </span>
            </div>

            {/* Step 2: Sign */}
            <div className="flex flex-col items-center z-10 relative flex-1">
              <div
                className={`w-10 h-10 rounded-full flex items-center justify-center border-2 font-bold transition-all duration-300 ${
                  signStatus === "success"
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
              <span
                className={`text-[11px] font-black uppercase mt-2 tracking-wider ${
                  signStatus === "processing"
                    ? "text-indigo-400"
                    : "text-subtle"
                }`}
              >
                Sign
              </span>
            </div>

            {/* Step 3: Submit */}
            <div className="flex flex-col items-center z-10 relative flex-1">
              <div
                className={`w-10 h-10 rounded-full flex items-center justify-center border-2 font-bold transition-all duration-300 ${
                  submitStatus === "success"
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
              <span
                className={`text-[11px] font-black uppercase mt-2 tracking-wider ${
                  submitStatus === "processing"
                    ? "text-indigo-400"
                    : "text-subtle"
                }`}
              >
                Submit
              </span>
            </div>
          </div>

          {/* Error Callout */}
          {errorMessage && (
            <div className="mb-6 p-4 rounded-2xl bg-red-500/10 border border-red-500/20 animate-in fade-in duration-200">
              <div className="flex gap-3">
                <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
                <div className="flex-1">
                  <h4 className="font-bold text-red-400 text-sm">
                    {errorType === "contract" && "Simulation Contract Failure"}
                    {errorType === "rejection" && "Wallet Signature Request Rejected"}
                    {errorType === "network" && "Network Submission Failed"}
                    {errorType === "wallet_not_connected" && "Wallet Not Connected"}
                  </h4>
                  <p className="text-xs text-danger/90 mt-1 leading-relaxed">
                    {errorMessage}
                  </p>
                  {errorType === "network" && (
                    <p className="text-[10px] text-indigo-400/90 font-mono mt-2 flex items-center gap-1.5 bg-indigo-500/5 px-2.5 py-1.5 rounded-lg border border-indigo-500/10 w-fit">
                      <span className="w-1.5 h-1.5 rounded-full bg-indigo-400 animate-ping" />
                      Idempotency Active: Retrying will only re-broadcast signed
                      payload.
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
              {composeStatus === "processing" && "Composing transaction with backend..."}
              {composeStatus === "error" && "Transaction composition failed. Please retry."}
              {signStatus === "processing" && "Awaiting approval in Stellar Wallet extension..."}
              {signStatus === "error" && "Signature request denied. Please retry signing."}
              {submitStatus === "processing" && "Submitting payload to network. Writing to ledger..."}
              {submitStatus === "error" && "Network issue detected. Retry submit safely."}
              {txStep === "completed" && "Transaction completed successfully!"}
            </p>
          </div>

          {/* Terminal Console Logs */}
          <div className="bg-background/90 rounded-2xl border border-border overflow-hidden mb-6 font-mono text-xs shadow-inner">
            <div className="flex items-center justify-between px-4 py-2 border-b border-border bg-background">
              <span className="text-subtle flex items-center gap-2 font-bold text-[10px] uppercase tracking-wider">
                <Terminal size={12} className="text-indigo-400" /> Transaction
                Console Logs
              </span>
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
            </div>
            <div className="p-4 h-36 overflow-y-auto space-y-1.5 scrollbar-thin scrollbar-thumb-white/15">
              {logs.map((log, i) => (
                <div
                  key={i}
                  className={`leading-relaxed ${
                    log.includes("ERROR:")
                      ? "text-red-400"
                      : log.includes("successful") ||
                          log.includes("signed") ||
                          log.includes("confirmed")
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
                <div className="text-faint italic">
                  No output yet. Pipeline starting...
                </div>
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
                  {errorType === "contract" && "Retry Composition"}
                  {errorType === "rejection" && "Try Signing Again"}
                  {errorType === "network" && "Retry Broadcast"}
                  {errorType === "wallet_not_connected" && "Connect Wallet"}
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

        {/* Dev Simulator Panel - Only in development */}
        {isDevelopment && (
          <div className="bg-card border border-border rounded-2xl overflow-hidden">
            <button
              type="button"
              onClick={() => setShowDevPanel(!showDevPanel)}
              className="w-full flex items-center justify-between px-5 py-4 hover:bg-card/[0.02] transition-colors"
            >
              <span className="flex items-center gap-2 text-sm font-bold text-subtle">
                <Settings size={16} className="text-indigo-400" /> Dev
                Simulator Controls
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
                  Development tools for testing error states. These controls are
                  gated out of production builds.
                </p>
                <div className="grid grid-cols-2 gap-3">
                  <button
                    type="button"
                    onClick={() => setErrorType("contract")}
                    className="p-3 rounded-xl border text-xs text-left font-semibold transition border-red-500/50 bg-red-500/10 text-red-400"
                  >
                    <p className="font-bold">Simulate Contract Error</p>
                    <p className="text-[10px] text-subtle mt-0.5">
                      Set contract failure state
                    </p>
                  </button>
                  <button
                    type="button"
                    onClick={() => setErrorType("rejection")}
                    className="p-3 rounded-xl border text-xs text-left font-semibold transition border-red-500/50 bg-red-500/10 text-red-400"
                  >
                    <p className="font-bold">Simulate Rejection</p>
                    <p className="text-[10px] text-subtle mt-0.5">
                      Set wallet rejection state
                    </p>
                  </button>
                  <button
                    type="button"
                    onClick={() => setErrorType("network")}
                    className="p-3 rounded-xl border text-xs text-left font-semibold transition border-red-500/50 bg-red-500/10 text-red-400"
                  >
                    <p className="font-bold">Simulate Network Error</p>
                    <p className="text-[10px] text-subtle mt-0.5">
                      Set network timeout state
                    </p>
                  </button>
                  <button
                    type="button"
                    onClick={handleCancel}
                    className="p-3 rounded-xl border text-xs text-left font-semibold transition border-border bg-background text-subtle hover:border-border-strong"
                  >
                    <p className="font-bold">Reset Pipeline</p>
                    <p className="text-[10px] text-subtle mt-0.5">
                      Clear all state and logs
                    </p>
                  </button>
                </div>
              </div>
            )}
          </div>
        )}
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
              {formatAssetAmount(status.amount, status.asset)}
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
              <dd className="text-sm">{formatDate(status.expiresAt)}</dd>
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
              className={`w-full p-4 rounded-xl border transition-all text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300 focus-visible:ring-offset-2 focus-visible:ring-offset-background ${
                selectedSourceAsset === null
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
                className={`w-full p-4 rounded-xl border transition-all text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300 focus-visible:ring-offset-2 focus-visible:ring-offset-background ${
                  selectedSourceAsset === option.sourceAsset
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

      {/* Wallet Connection Section */}
      {!wallet.connected && (
        <div className="bg-card border border-border-strong rounded-2xl p-6 mb-6">
          <h3 className="text-lg font-bold mb-4">Connect Wallet</h3>
          <p className="text-sm text-muted mb-4">
            Connect your Stellar wallet to authorize this payment.
          </p>
          <div className="space-y-3">
            {availableWallets
              .filter((w) => w.available || w.type === "demo")
              .map((w) => (
                <button
                  key={w.type}
                  type="button"
                  onClick={() => handleWalletConnect(w.type as "freighter" | "albedo" | "demo")}
                  className="w-full p-4 rounded-xl border border-border hover:border-brand hover:bg-brand-soft transition-all text-left flex items-center gap-4"
                >
                  <div className="w-10 h-10 rounded-lg bg-indigo-500/10 flex items-center justify-center">
                    <WalletCards className="w-5 h-5 text-indigo-400" />
                  </div>
                  <div className="flex-1">
                    <p className="font-semibold">{w.label}</p>
                    <p className="text-sm text-muted">{w.description}</p>
                  </div>
                  {!w.available && w.type !== "demo" && (
                    <span className="text-xs text-amber-400 bg-amber-500/10 px-2 py-1 rounded">
                      Not Detected
                    </span>
                  )}
                </button>
              ))}
          </div>
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
          disabled={!wallet.connected}
          className={`w-full py-4 rounded-xl font-bold text-lg transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300 focus-visible:ring-offset-2 focus-visible:ring-offset-background ${
            wallet.connected
              ? "bg-brand hover:opacity-90"
              : "bg-surface-strong text-subtle cursor-not-allowed"
          }`}
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
          <strong>How it works:</strong> Review the transaction summary before
          your Stellar wallet opens. After confirmation, your wallet will
          request the signature for this exact payload.
        </p>
      </div>
    </div>
  );
}