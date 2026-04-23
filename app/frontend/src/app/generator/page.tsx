"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { QRPreview } from "@/components/QRPreview";
import { NetworkBadge } from "@/components/NetworkBadge";
import { useApi } from "@/hooks/useApi";
import { getQuickexApiBase } from "@/lib/api";
import '@/lib/i18n';
import { useTranslation } from 'react-i18next';

type ValidationErrors = Partial<
  Record<"amount" | "asset" | "destination", string>
>;

type VerifiedAsset = {
  code: string;
  type: string;
  issuer: string | null;
  verified: boolean;
  decimals: number;
};

type PathRow = {
  sourceAmount: string;
  sourceAsset: string;
  destinationAmount: string;
  destinationAsset: string;
  hopCount: number;
  pathHops: string[];
  rateDescription: string;
};

type PathPreviewResponse = {
  paths: PathRow[];
  horizonUrl: string;
};

type LinkMetadataSuccess = {
  success: true;
  data: {
    canonical: string;
    amount: string;
    asset: string;
    destination?: string | null;
    memo: string | null;
    metadata?: Record<string, unknown>;
  };
};

type ComposeSuccess = {
  success: true;
  unsignedXdr?: string;
  feeEstimate?: {
    totalFeeXLM?: string;
    totalFee?: string;
  };
  resourceEstimate?: Record<string, number>;
  simulationLatencyMs?: number;
};

type ComposeError = {
  success: false;
  userMessage?: string;
  error?: string;
};

export default function Generator() {
  const { t } = useTranslation();
  const apiBase = useMemo(() => getQuickexApiBase(), []);
  const { error, loading, callApi, data } = useApi<LinkMetadataSuccess>();

  const [form, setForm] = useState({
    amount: "",
    destination: "",
    memo: "",
  });

  const [recipientAssetCode, setRecipientAssetCode] = useState("USDC");
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [sourceAssetCodes, setSourceAssetCodes] = useState<Set<string>>(
    () => new Set(["XLM", "USDC"]),
  );

  const [verifiedAssets, setVerifiedAssets] = useState<VerifiedAsset[]>([]);
  const [assetsLoading, setAssetsLoading] = useState(true);
  const [assetsError, setAssetsError] = useState<string | null>(null);

  const [pathLoading, setPathLoading] = useState(false);
  const [pathError, setPathError] = useState<string | null>(null);
  const [pathData, setPathData] = useState<PathPreviewResponse | null>(null);

  const [preflightAccount, setPreflightAccount] = useState("");
  const [preflightLoading, setPreflightLoading] = useState(false);
  const [preflightResult, setPreflightResult] = useState<
    ComposeSuccess | ComposeError | null
  >(null);
  const [preflightUnavailable, setPreflightUnavailable] = useState<
    string | null
  >(null);

  const [errors, setErrors] = useState<ValidationErrors>({});

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setAssetsLoading(true);
      setAssetsError(null);
      try {
        const res = await fetch(`${apiBase}/stellar/verified-assets`);
        if (!res.ok) {
          throw new Error(`HTTP ${res.status}`);
        }
        const json = (await res.json()) as { assets: VerifiedAsset[] };
        if (!cancelled) {
          setVerifiedAssets(json.assets ?? []);
        }
      } catch {
        if (!cancelled) {
          setAssetsError(t('couldNotLoadAssets'));
          setVerifiedAssets([]);
        }
      } finally {
        if (!cancelled) {
          setAssetsLoading(false);
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [apiBase]);

  const recipientRef = useMemo(() => {
    const a = verifiedAssets.find(
      (x) => x.code.toUpperCase() === recipientAssetCode.toUpperCase(),
    );
    return a
      ? { code: a.code, issuer: a.issuer ?? undefined }
      : { code: recipientAssetCode };
  }, [verifiedAssets, recipientAssetCode]);

  const sourceRefsForPreview = useMemo(() => {
    const refs: { code: string; issuer?: string }[] = [];
    for (const code of sourceAssetCodes) {
      const a = verifiedAssets.find(
        (x) => x.code.toUpperCase() === code.toUpperCase(),
      );
      if (a) {
        refs.push({
          code: a.code,
          issuer: a.issuer ?? undefined,
        });
      }
    }
    return refs;
  }, [sourceAssetCodes, verifiedAssets]);

  const fetchPathPreview = useCallback(async () => {
    if (
      !advancedOpen ||
      !form.amount ||
      Number.isNaN(Number(form.amount)) ||
      sourceRefsForPreview.length === 0
    ) {
      setPathData(null);
      return;
    }
    setPathLoading(true);
    setPathError(null);
    try {
      const res = await fetch(`${apiBase}/stellar/path-preview`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          destinationAmount: form.amount.trim(),
          destinationAsset: recipientRef,
          sourceAssets: sourceRefsForPreview,
        }),
      });
      const json = await res.json().catch(() => ({}));
      if (!res.ok) {
        const msg =
          typeof json?.message === "string"
            ? json.message
            : "Path preview failed.";
        throw new Error(msg);
      }
      setPathData(json as PathPreviewResponse);
    } catch (e) {
      setPathError(e instanceof Error ? e.message : "Path preview failed.");
      setPathData(null);
    } finally {
      setPathLoading(false);
    }
  }, [
    advancedOpen,
    apiBase,
    form.amount,
    recipientRef,
    sourceRefsForPreview,
  ]);

  useEffect(() => {
    if (!advancedOpen) {
      return;
    }
    const t = window.setTimeout(() => {
      void fetchPathPreview();
    }, 450);
    return () => window.clearTimeout(t);
  }, [advancedOpen, fetchPathPreview]);

  const validate = () => {
    const newErrors: ValidationErrors = {};
    if (!form.amount) {
      newErrors.amount = t('amountRequired');
    } else if (Number.isNaN(Number(form.amount))) {
      newErrors.amount = t('enterValidNumber');
    }
    if (!form.destination) {
      newErrors.destination = t('destinationRequired');
    }
    if (!recipientAssetCode) {
      newErrors.asset = t('selectRecipientAsset');
    }
    return newErrors;
  };

  const linkData = useMemo(() => {
    if (!form.amount || !recipientAssetCode || !form.destination) {
      return "";
    }
    const recipient = verifiedAssets.find(
      (x) => x.code.toUpperCase() === recipientAssetCode.toUpperCase(),
    );
    return JSON.stringify({
      amount: form.amount,
      asset: recipientAssetCode,
      destination: form.destination,
      memo: form.memo,
      ...(advancedOpen && {
        pathPayment: {
          recipientAsset: recipient
            ? {
                code: recipient.code,
                type: recipient.type,
                issuer: recipient.issuer,
              }
            : { code: recipientAssetCode },
          allowedSourceAssets: Array.from(sourceAssetCodes),
        },
      }),
    });
  }, [
    form.amount,
    form.destination,
    form.memo,
    recipientAssetCode,
    verifiedAssets,
    advancedOpen,
    sourceAssetCodes,
  ]);

  const handleSubmit = () => {
    const validation = validate();
    setErrors(validation);
    if (Object.keys(validation).length > 0) {
      return;
    }

    callApi(async () => {
      const res = await fetch(`${apiBase}/links/metadata`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          amount: Number(form.amount),
          asset: recipientAssetCode,
          destination: form.destination,
          memo: form.memo || undefined,
        }),
      });
      const json = await res.json();
      if (!res.ok) {
        const msg =
          json?.message ??
          json?.error ??
          `Request failed (${res.status})`;
        throw new Error(typeof msg === "string" ? msg : "Request failed");
      }
      return json as LinkMetadataSuccess;
    });
  };

  const runPreflight = async () => {
    const pk = preflightAccount.trim();
    if (!/^G[A-Z0-9]{55}$/.test(pk)) {
      setPreflightResult({
        success: false,
        userMessage: t('invalidPublicKey'),
      });
      return;
    }
    setPreflightLoading(true);
    setPreflightResult(null);
    setPreflightUnavailable(null);
    try {
      const res = await fetch(`${apiBase}/stellar/soroban-preflight`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sourceAccount: pk }),
      });
      const json = (await res.json()) as ComposeSuccess | ComposeError | {
        message?: string;
        code?: string;
      };
      if (res.status === 503) {
        setPreflightUnavailable(
          typeof json?.message === "string"
            ? json.message
            : t('preflightUnavailable'),
        );
        return;
      }
      if (!res.ok) {
        setPreflightResult({
          success: false,
          userMessage:
            typeof json?.message === "string"
              ? json.message
              : t('preflightFailed'),
        });
        return;
      }
      setPreflightResult(json as ComposeSuccess | ComposeError);
    } catch {
      setPreflightResult({
        success: false,
        userMessage: t('networkError'),
      });
    } finally {
      setPreflightLoading(false);
    }
  };

  const toggleSource = (code: string) => {
    setSourceAssetCodes((prev) => {
      const next = new Set(prev);
      if (next.has(code)) {
        if (next.size <= 1) {
          return next;
        }
        next.delete(code);
      } else {
        next.add(code);
      }
      return next;
    });
  };

  const canonicalPreview =
    data?.success === true ? data.data.canonical : null;

  return (
    <div className="relative min-h-screen text-white selection:bg-indigo-500/30 overflow-x-hidden">
      <NetworkBadge />

      <div className="fixed top-[-20%] left-[-30%] w-[60%] h-[60%] bg-indigo-500/10 blur-[120px]" />
      <div className="fixed bottom-[-20%] right-[-30%] w-[50%] h-[50%] bg-purple-500/5 blur-[100px]" />

      <aside className="hidden md:flex w-72 h-screen border-r border-white/5 bg-black/20 backdrop-blur-3xl flex-col fixed left-0 top-0 z-20">
        <nav className="flex-1 px-4 py-20 space-y-2">
          <Link
            href="/dashboard"
            className="flex items-center gap-3 px-4 py-3 text-neutral-500 hover:text-white hover:bg-white/5 rounded-2xl font-semibold"
          >
            <span>📊</span> {t('dashboard')}
          </Link>
          <Link
            href="/generator"
            className="flex items-center gap-3 px-4 py-3 bg-white/5 text-white rounded-2xl font-bold border border-white/5 shadow-inner"
          >
            <span className="text-indigo-400">⚡</span> {t('linkGenerator')}
          </Link>
          <Link href="/settings" className="flex items-center gap-3 px-4 py-3 text-neutral-500 hover:text-white hover:bg-white/5 rounded-2xl font-semibold">
            <span>⚙️</span> {t('profileSettings')}
          </Link>
        </nav>
      </aside>

      <main className="relative z-10 px-4 sm:px-6 md:px-12 pt-10 md:ml-72">
        <header className="mb-10 sm:mb-16 max-w-3xl">
          <nav className="flex items-center gap-2 text-xs font-black text-neutral-600 uppercase tracking-widest mb-4">
            <span>{t('services')}</span>
            <span>/</span>
            <span className="text-neutral-400">{t('linkGenerator')}</span>
          </nav>

          <h1 className="text-4xl sm:text-5xl md:text-6xl font-black tracking-tight mb-4">
            {t('createPayment')} <br />
            <span className="bg-gradient-to-r from-indigo-400 to-purple-400 bg-clip-text text-transparent">
              {t('requestInstantly')}
            </span>
          </h1>

          <p className="text-neutral-500 text-lg max-w-xl">
            {t('advancedModeDescription')}
          </p>
        </header>

        <div className="grid grid-cols-1 xl:grid-cols-[1.2fr_0.8fr] gap-12 xl:gap-20 max-w-7xl">
          <div className="space-y-12">
            <section className="space-y-6">
              <div>
                <label className="text-xs font-black uppercase tracking-widest text-neutral-500 ml-1">
                  {t('amountLabel')}
                </label>

                <div className="relative group mt-2">
                  <div className="absolute -inset-0.5 bg-gradient-to-r from-indigo-500/20 to-purple-500/20 rounded-3xl blur opacity-0 group-focus-within:opacity-100 transition" />

                  <div className="relative bg-neutral-900/50 border border-white/10 rounded-3xl p-1 shadow-2xl">
                    <input
                      type="number"
                      placeholder={t('amountPlaceholder')}
                      value={form.amount}
                      onChange={(e) =>
                        setForm({ ...form, amount: e.target.value })
                      }
                      className="w-full bg-transparent p-6 sm:p-8 text-3xl sm:text-5xl font-black focus:outline-none placeholder:text-neutral-800"
                    />

                    <div className="absolute right-4 top-1/2 -translate-y-1/2 flex bg-black/40 p-2 rounded-2xl border border-white/5 backdrop-blur-xl gap-1 max-w-[50%] flex-wrap justify-end">
                      {assetsLoading ? (
                        <span className="px-3 py-2 text-xs text-neutral-500">
                          {t('loadingAssets')}
                        </span>
                      ) : (
                        verifiedAssets.map((a) => (
                          <button
                            key={a.code}
                            type="button"
                            onClick={() => setRecipientAssetCode(a.code)}
                            className={`
                            px-3 py-2 text-xs sm:text-sm rounded-xl transition 
                            ${
                              recipientAssetCode === a.code
                                ? "bg-white text-black font-black"
                                : "text-neutral-500 hover:text-white"
                            }
                          `}
                          >
                            {a.code}
                          </button>
                        ))
                      )}
                    </div>
                  </div>
                </div>

                {errors.amount && (
                  <p className="text-red-500 text-xs mt-2">{errors.amount}</p>
                )}
                {assetsError && (
                  <p className="text-amber-500 text-xs mt-2">{assetsError}</p>
                )}
              </div>

              <div>
                <label className="text-xs font-black uppercase tracking-widest text-neutral-500 ml-1">
                  {t('destinationLabel')}
                </label>
                <input
                  type="text"
                  placeholder={t('destinationPlaceholder')}
                  value={form.destination}
                  onChange={(e) =>
                    setForm({ ...form, destination: e.target.value })
                  }
                  className="w-full bg-neutral-900/30 border border-white/10 rounded-3xl p-5 font-bold mt-2 focus:outline-none placeholder:text-neutral-700"
                />
                {errors.destination && (
                  <p className="text-red-500 text-xs mt-2">
                    {errors.destination}
                  </p>
                )}
              </div>

              <div>
                <label className="text-xs font-black uppercase tracking-widest text-neutral-500 ml-1">
                  {t('memoLabel')}
                </label>
                <input
                  type="text"
                  placeholder={t('memoPlaceholder')}
                  value={form.memo}
                  onChange={(e) => setForm({ ...form, memo: e.target.value })}
                  className="w-full bg-neutral-900/30 border border-white/10 rounded-3xl p-5 font-bold mt-2 focus:outline-none placeholder:text-neutral-700"
                />
              </div>

              <div className="rounded-3xl border border-white/10 bg-black/30 p-6 space-y-4">
                <button
                  type="button"
                  onClick={() => setAdvancedOpen((v) => !v)}
                  className="flex w-full items-center justify-between text-left"
                >
                  <span className="text-sm font-black uppercase tracking-widest text-indigo-300">
                    {t('advancedSettings')}
                  </span>
                  <span className="text-neutral-500 text-sm">
                    {advancedOpen ? t('hide') : t('show')} path payments
                  </span>
                </button>

                {advancedOpen && (
                  <div className="space-y-6 pt-2 border-t border-white/5">
                    <div>
                      <p className="text-xs font-bold uppercase tracking-wider text-neutral-500 mb-2">
                        {t('recipientAsset')}
                      </p>
                      <p className="text-sm text-neutral-400 mb-3">
                        {t('recipientAssetDescription')}
                      </p>
                      <select
                        value={recipientAssetCode}
                        onChange={(e) =>
                          setRecipientAssetCode(e.target.value)
                        }
                        className="w-full bg-neutral-900 border border-white/10 rounded-2xl p-4 font-bold focus:outline-none focus:ring-2 focus:ring-indigo-500/40"
                      >
                        {verifiedAssets.map((a) => (
                          <option key={a.code} value={a.code}>
                            {a.code}
                            {a.type !== "native" && a.issuer
                              ? ` (${a.issuer.slice(0, 4)}…)`
                              : ""}
                          </option>
                        ))}
                      </select>
                      {errors.asset && (
                        <p className="text-red-500 text-xs mt-2">
                          {errors.asset}
                        </p>
                      )}
                    </div>

                    <div>
                      <p className="text-xs font-bold uppercase tracking-wider text-neutral-500 mb-2">
                        {t('allowedSourceAssets')}
                      </p>
                      <p className="text-sm text-neutral-400 mb-3">
                        {t('allowedSourceAssetsDescription')}
                      </p>
                      <div className="flex flex-wrap gap-2">
                        {verifiedAssets.map((a) => {
                          const on = sourceAssetCodes.has(a.code);
                          return (
                            <button
                              key={a.code}
                              type="button"
                              onClick={() => toggleSource(a.code)}
                              className={`px-4 py-2 rounded-xl text-sm font-bold border transition ${
                                on
                                  ? "bg-indigo-500/30 border-indigo-400/50 text-white"
                                  : "bg-neutral-900/50 border-white/10 text-neutral-500 hover:text-neutral-300"
                              }`}
                            >
                              {a.code}
                            </button>
                          );
                        })}
                      </div>
                    </div>

                    <div className="rounded-2xl border border-white/10 bg-neutral-950/60 p-4 space-y-3">
                      <div className="flex items-center justify-between">
                        <h3 className="text-xs font-black uppercase tracking-widest text-neutral-400">
                          {t('pathPreview')}
                        </h3>
                        {pathLoading && (
                          <span className="text-xs text-indigo-300 animate-pulse">
                            {t('fetchingEstimates')}
                          </span>
                        )}
                      </div>
                      {pathError && (
                        <p className="text-amber-500 text-sm">{pathError}</p>
                      )}
                      {!pathLoading &&
                        !pathError &&
                        pathData &&
                        pathData.paths.length === 0 && (
                          <p className="text-neutral-500 text-sm">
                            {t('noPathsFound', { horizonUrl: pathData.horizonUrl })}
                          </p>
                        )}
                      {pathData && pathData.paths.length > 0 && (
                        <ul className="space-y-3 max-h-64 overflow-y-auto pr-1">
                          {pathData.paths.map((p, i) => (
                            <li
                              key={`${p.sourceAsset}-${i}`}
                              className="rounded-xl bg-black/40 border border-white/5 p-3 text-sm"
                            >
                              <div className="font-mono text-neutral-300">
                                {t('payReceive', {
                                  sourceAmount: p.sourceAmount,
                                  sourceAsset: p.sourceAsset,
                                  destinationAmount: p.destinationAmount,
                                  destinationAsset: p.destinationAsset
                                })}
                              </div>
                              <div className="text-xs text-neutral-500 mt-1">
                                {t('hops', { hopCount: p.hopCount })}
                                {p.pathHops.length > 0
                                  ? ` · ${p.pathHops.join(" → ")}`
                                  : ""}
                              </div>
                              <div className="text-xs text-neutral-600 mt-1">
                                {p.rateDescription}
                              </div>
                            </li>
                          ))}
                        </ul>
                      )}
                    </div>

                    <div className="rounded-2xl border border-white/10 bg-neutral-950/60 p-4 space-y-3">
                      <h3 className="text-xs font-black uppercase tracking-widest text-neutral-400">
                        {t('sorobanPreflight')}
                      </h3>
                      <p className="text-xs text-neutral-500">
                        {t('sorobanPreflightDescription')}
                      </p>
                      <input
                        type="text"
                        placeholder={t('sourceAccountPlaceholder')}
                        value={preflightAccount}
                        onChange={(e) => setPreflightAccount(e.target.value)}
                        className="w-full bg-neutral-900/80 border border-white/10 rounded-xl p-3 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/30"
                      />
                      <button
                        type="button"
                        onClick={() => void runPreflight()}
                        disabled={preflightLoading}
                        className="w-full py-3 rounded-xl bg-white/10 hover:bg-white/15 border border-white/10 text-sm font-bold disabled:opacity-50"
                      >
                        {preflightLoading
                          ? t('simulating')
                          : t('runPreflight')}
                      </button>
                      {preflightUnavailable && (
                        <p className="text-amber-500 text-sm">
                          {preflightUnavailable}
                        </p>
                      )}
                      {preflightResult && preflightResult.success === false && (
                        <p className="text-red-400 text-sm">
                          {preflightResult.userMessage ??
                            preflightResult.error ??
                            t('simulationFailed')}
                        </p>
                      )}
                      {preflightResult && preflightResult.success === true && (
                        <div className="text-sm text-emerald-400 space-y-1">
                          <p>{t('simulationOk')}</p>
                          {preflightResult.feeEstimate?.totalFeeXLM && (
                            <p className="font-mono text-neutral-300">
                              {t('totalFee', { totalFee: preflightResult.feeEstimate.totalFeeXLM })}
                            </p>
                          )}
                          {typeof preflightResult.simulationLatencyMs ===
                            "number" && (
                            <p className="text-xs text-neutral-500">
                              {t('latency', { latency: preflightResult.simulationLatencyMs })}
                            </p>
                          )}
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            </section>

            <button
              onClick={handleSubmit}
              disabled={loading}
              className="w-full py-6 bg-white text-black text-3xl font-black rounded-3xl hover:bg-neutral-200 active:scale-95 transition disabled:opacity-60"
            >
              {loading ? "Generating…" : "Generate Payment Link"}
            </button>
            {error && (
              <p className="text-red-500 text-sm text-center">{error}</p>
            )}
          </div>

          <div className="space-y-12">
            <div className="w-full max-w-sm mx-auto">
              <QRPreview value={linkData} />
            </div>

            <div className="space-y-4 p-8 rounded-3xl bg-black/40 border border-white/5 backdrop-blur-xl">
              <label className="text-[10px] font-black uppercase tracking-widest text-neutral-600">
                Canonical query (from API)
              </label>

              <div className="bg-neutral-900 border border-white/5 p-4 rounded-xl font-mono text-neutral-400 text-xs break-all min-h-[3rem]">
                {canonicalPreview ?? (
                  <span className="text-neutral-600 italic">
                    Generate to fetch metadata from the backend.
                  </span>
                )}
              </div>

              <button
                type="button"
                disabled={!canonicalPreview}
                onClick={() => {
                  if (canonicalPreview && navigator.clipboard) {
                    void navigator.clipboard.writeText(canonicalPreview);
                  }
                }}
                className="w-full py-3 bg-white/10 text-white rounded-xl border border-white/5 text-xs uppercase tracking-widest hover:bg-white/15 disabled:opacity-40 disabled:cursor-not-allowed"
              >
                Copy canonical params
              </button>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
