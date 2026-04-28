"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { QRPreview } from "@/components/QRPreview";
import { NetworkBadge } from "@/components/NetworkBadge";
import { useApi } from "@/hooks/useApi";
import { getQuickexApiBase } from "@/lib/api";
import {
  buildInvoicePreview,
  calculateTemplateSubtotal,
  calculateTemplateTax,
  calculateTemplateTotal,
  CUSTOMER_STORAGE_KEY,
  CustomerProfile,
  DEFAULT_CUSTOMERS,
  DEFAULT_TEMPLATES,
  formatCurrencyAmount,
  InvoiceLineItem,
  InvoiceTemplate,
  TEMPLATE_STORAGE_KEY,
  toBulkLinkPayload,
} from "./bulk-invoicing";
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

const QUOTE_TTL_SECONDS = 25;
const BASE_PATH_OPERATION_FEE_XLM = 0.00001;
const FOCUS_RING_CLASS =
  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300 focus-visible:ring-offset-2 focus-visible:ring-offset-black";

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

type BulkGenerateSuccess = {
  success: boolean;
  total: number;
  links: Array<{
    id: string;
    url: string;
    canonical: string;
    amount: string;
    asset: string;
    username?: string;
    destination?: string;
    referenceId?: string;
  }>;
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
  const [quoteFetchedAt, setQuoteFetchedAt] = useState<number | null>(null);
  const [quoteNow, setQuoteNow] = useState<number>(() => Date.now());
  const [slippagePct, setSlippagePct] = useState("0.50");

  const [preflightAccount, setPreflightAccount] = useState("");
  const [preflightLoading, setPreflightLoading] = useState(false);
  const [preflightResult, setPreflightResult] = useState<
    ComposeSuccess | ComposeError | null
  >(null);
  const [preflightUnavailable, setPreflightUnavailable] = useState<
    string | null
  >(null);

  const [errors, setErrors] = useState<ValidationErrors>({});
  const [templates, setTemplates] = useState<InvoiceTemplate[]>(DEFAULT_TEMPLATES);
  const [customers, setCustomers] = useState<CustomerProfile[]>(DEFAULT_CUSTOMERS);
  const [selectedTemplateId, setSelectedTemplateId] = useState(
    DEFAULT_TEMPLATES[0]?.id ?? "",
  );
  const [selectedCustomerIds, setSelectedCustomerIds] = useState<string[]>(
    DEFAULT_CUSTOMERS.map((customer) => customer.id),
  );
  const [editingTemplateId, setEditingTemplateId] = useState<string | null>(null);
  const [editingCustomerId, setEditingCustomerId] = useState<string | null>(null);
  const [bulkLoading, setBulkLoading] = useState(false);
  const [bulkError, setBulkError] = useState<string | null>(null);
  const [bulkResult, setBulkResult] = useState<BulkGenerateSuccess | null>(null);
  const [templateForm, setTemplateForm] = useState({
    name: "Monthly Hosting",
    asset: "USDC",
    notes: "Net 7 payment terms.",
    taxRate: "7.5",
    lineItemsText: "Hosting retainer|1|120\nSupport hours|3|40",
  });
  const [customerForm, setCustomerForm] = useState({
    name: "",
    email: "",
    address: "",
    username: "",
  });

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
  }, [apiBase, t]);

  useEffect(() => {
    try {
      const storedTemplates = window.localStorage.getItem(TEMPLATE_STORAGE_KEY);
      const storedCustomers = window.localStorage.getItem(CUSTOMER_STORAGE_KEY);
      if (storedTemplates) {
        const parsed = JSON.parse(storedTemplates) as InvoiceTemplate[];
        if (parsed.length > 0) {
          setTemplates(parsed);
          setSelectedTemplateId(parsed[0].id);
        }
      }
      if (storedCustomers) {
        const parsed = JSON.parse(storedCustomers) as CustomerProfile[];
        if (parsed.length > 0) {
          setCustomers(parsed);
          setSelectedCustomerIds(parsed.map((customer) => customer.id));
        }
      }
    } catch {
      // Preserve defaults if local storage is unavailable or malformed.
    }
  }, []);

  useEffect(() => {
    window.localStorage.setItem(TEMPLATE_STORAGE_KEY, JSON.stringify(templates));
  }, [templates]);

  useEffect(() => {
    window.localStorage.setItem(CUSTOMER_STORAGE_KEY, JSON.stringify(customers));
  }, [customers]);

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
      setQuoteFetchedAt(null);
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
      setQuoteFetchedAt(Date.now());
    } catch (e) {
      setPathError(e instanceof Error ? e.message : "Path preview failed.");
      setPathData(null);
      setQuoteFetchedAt(null);
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

  useEffect(() => {
    if (!advancedOpen || !quoteFetchedAt) {
      return;
    }
    const interval = window.setInterval(() => {
      setQuoteNow(Date.now());
    }, 1000);
    return () => window.clearInterval(interval);
  }, [advancedOpen, quoteFetchedAt]);

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
    if (advancedOpen && Number(slippagePct) >= 5) {
      setErrors((prev) => ({
        ...prev,
        amount: t('lowerSlippageToContinue'),
      }));
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
      const message =
        typeof json === "object" &&
        json !== null &&
        "message" in json &&
        typeof json.message === "string"
          ? json.message
          : null;
      if (res.status === 503) {
        setPreflightUnavailable(
          message ?? t('preflightUnavailable'),
        );
        return;
      }
      if (!res.ok) {
        setPreflightResult({
          success: false,
          userMessage: message ?? t('preflightFailed'),
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

  const slippageValue = Number(slippagePct);
  const slippageWarningLevel =
    slippageValue >= 5 ? "block" : slippageValue >= 2 ? "warn" : "safe";
  const slippageWarningText =
    slippageWarningLevel === "block"
      ? t('slippageTooHigh')
      : slippageWarningLevel === "warn"
        ? t('slippageWarning')
        : null;

  const quoteExpiresAt = quoteFetchedAt
    ? quoteFetchedAt + QUOTE_TTL_SECONDS * 1000
    : null;
  const quoteSecondsRemaining = quoteExpiresAt
    ? Math.max(0, Math.ceil((quoteExpiresAt - quoteNow) / 1000))
    : null;
  const quoteExpired =
    quoteSecondsRemaining !== null && quoteSecondsRemaining <= 0;

  const pathErrorType = useMemo(() => {
    const txt = pathError?.toLowerCase() ?? "";
    if (txt.includes("liquidity")) {
      return "liquidity";
    }
    if (txt.includes("no path") || txt.includes("strict-receive")) {
      return "path";
    }
    return "generic";
  }, [pathError]);

  const selectedTemplate = useMemo(
    () => templates.find((template) => template.id === selectedTemplateId) ?? null,
    [selectedTemplateId, templates],
  );

  const selectedCustomers = useMemo(
    () => customers.filter((customer) => selectedCustomerIds.includes(customer.id)),
    [customers, selectedCustomerIds],
  );

  const invoicePreviewRows = useMemo(() => {
    if (!selectedTemplate) {
      return [];
    }

    return selectedCustomers.map((customer, index) =>
      buildInvoicePreview(selectedTemplate, customer, index),
    );
  }, [selectedCustomers, selectedTemplate]);

  const previewGenerationPayload = useMemo(
    () => invoicePreviewRows.map((row) => toBulkLinkPayload(row)),
    [invoicePreviewRows],
  );

  const getPathLegs = (path: PathRow) => {
    const route = [path.sourceAsset, ...path.pathHops, path.destinationAsset];
    return route.slice(0, -1).map((fromAsset, idx) => ({
      fromAsset,
      toAsset: route[idx + 1],
      poolLabel: `Pool ${idx + 1}`,
    }));
  };

  const parseLineItems = (lineItemsText: string): InvoiceLineItem[] =>
    lineItemsText
      .split("\n")
      .map((line, index) => {
        const [description, quantity, unitPrice] = line.split("|").map((part) => part.trim());
        if (!description || !quantity || !unitPrice) {
          return null;
        }
        return {
          id: `line-${Date.now()}-${index}`,
          description,
          quantity: Number(quantity),
          unitPrice: Number(unitPrice),
        };
      })
      .filter((item): item is InvoiceLineItem => Boolean(item));

  const resetTemplateForm = () => {
    setTemplateForm({
      name: "",
      asset: "USDC",
      notes: "",
      taxRate: "0",
      lineItemsText: "",
    });
    setEditingTemplateId(null);
  };

  const resetCustomerForm = () => {
    setCustomerForm({
      name: "",
      email: "",
      address: "",
      username: "",
    });
    setEditingCustomerId(null);
  };

  const saveTemplate = () => {
    const lineItems = parseLineItems(templateForm.lineItemsText);
    if (!templateForm.name.trim() || lineItems.length === 0) {
      setBulkError("Template name and at least one valid line item are required.");
      return;
    }

    const nextTemplate: InvoiceTemplate = {
      id: editingTemplateId ?? `template-${Date.now()}`,
      name: templateForm.name.trim(),
      asset: templateForm.asset.trim() || "USDC",
      notes: templateForm.notes.trim(),
      taxRate: Number(templateForm.taxRate) || 0,
      lineItems,
    };

    setTemplates((current) => {
      const remaining = current.filter((template) => template.id !== nextTemplate.id);
      return [...remaining, nextTemplate];
    });
    setSelectedTemplateId(nextTemplate.id);
    setBulkError(null);
    resetTemplateForm();
  };

  const editTemplate = (template: InvoiceTemplate) => {
    setEditingTemplateId(template.id);
    setTemplateForm({
      name: template.name,
      asset: template.asset,
      notes: template.notes,
      taxRate: String(template.taxRate),
      lineItemsText: template.lineItems
        .map((item) => `${item.description}|${item.quantity}|${item.unitPrice}`)
        .join("\n"),
    });
  };

  const deleteTemplate = (templateId: string) => {
    const nextTemplates = templates.filter((template) => template.id !== templateId);
    setTemplates(nextTemplates.length > 0 ? nextTemplates : DEFAULT_TEMPLATES);
    if (selectedTemplateId === templateId) {
      setSelectedTemplateId((nextTemplates[0] ?? DEFAULT_TEMPLATES[0]).id);
    }
  };

  const saveCustomer = () => {
    if (!customerForm.name.trim() || !customerForm.email.trim()) {
      setBulkError("Customer name and email are required.");
      return;
    }

    const nextCustomer: CustomerProfile = {
      id: editingCustomerId ?? `customer-${Date.now()}`,
      name: customerForm.name.trim(),
      email: customerForm.email.trim(),
      address: customerForm.address.trim(),
      username: customerForm.username.trim(),
    };

    setCustomers((current) => {
      const remaining = current.filter((customer) => customer.id !== nextCustomer.id);
      return [...remaining, nextCustomer];
    });
    setSelectedCustomerIds((current) =>
      current.includes(nextCustomer.id) ? current : [...current, nextCustomer.id],
    );
    setBulkError(null);
    resetCustomerForm();
  };

  const editCustomer = (customer: CustomerProfile) => {
    setEditingCustomerId(customer.id);
    setCustomerForm({
      name: customer.name,
      email: customer.email,
      address: customer.address,
      username: customer.username,
    });
  };

  const deleteCustomer = (customerId: string) => {
    setCustomers((current) => current.filter((customer) => customer.id !== customerId));
    setSelectedCustomerIds((current) => current.filter((id) => id !== customerId));
  };

  const toggleCustomerSelection = (customerId: string) => {
    setSelectedCustomerIds((current) =>
      current.includes(customerId)
        ? current.filter((id) => id !== customerId)
        : [...current, customerId],
    );
  };

  const generateBulkInvoices = async () => {
    if (!selectedTemplate) {
      setBulkError("Choose a template before generating invoices.");
      return;
    }

    if (previewGenerationPayload.length === 0) {
      setBulkError("Select at least one saved customer for bulk generation.");
      return;
    }

    if (previewGenerationPayload.some((item) => !item.username && !item.destination)) {
      setBulkError("Each selected customer needs either a username or a Stellar address.");
      return;
    }

    setBulkLoading(true);
    setBulkError(null);

    try {
      const response = await fetch(`${apiBase}/links/bulk/generate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ links: previewGenerationPayload }),
      });
      const payload = (await response.json()) as BulkGenerateSuccess & {
        message?: string;
      };
      if (!response.ok) {
        throw new Error(payload.message ?? `Bulk generation failed (${response.status})`);
      }
      setBulkResult(payload);
    } catch (generationError) {
      setBulkError(
        generationError instanceof Error
          ? generationError.message
          : "Unable to generate invoices.",
      );
      setBulkResult(null);
    } finally {
      setBulkLoading(false);
    }
  };

  return (
    <div className="relative min-h-screen text-white selection:bg-indigo-500/30 overflow-x-hidden">
      <a
        href="#generator-main"
        className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-50 focus:rounded-lg focus:bg-indigo-500 focus:px-3 focus:py-2 focus:text-sm focus:font-semibold focus:text-white"
      >
        Skip to payment form
      </a>
      <NetworkBadge />

      <div className="fixed top-[-20%] left-[-30%] w-[60%] h-[60%] bg-indigo-500/10 blur-[120px]" />
      <div className="fixed bottom-[-20%] right-[-30%] w-[50%] h-[50%] bg-purple-500/5 blur-[100px]" />

      <aside className="hidden md:flex w-72 h-screen border-r border-white/5 bg-black/20 backdrop-blur-3xl flex-col fixed left-0 top-0 z-20">
        <nav className="flex-1 px-4 py-20 space-y-2" aria-label="Generator navigation">
          <Link
            href="/dashboard"
            className={`flex items-center gap-3 px-4 py-3 text-neutral-300 hover:text-white hover:bg-white/5 rounded-2xl font-semibold ${FOCUS_RING_CLASS}`}
          >
            <span>📊</span> {t('dashboard')}
          </Link>
          <Link
            href="/generator"
            aria-current="page"
            className={`flex items-center gap-3 px-4 py-3 bg-white/5 text-white rounded-2xl font-bold border border-white/5 shadow-inner ${FOCUS_RING_CLASS}`}
          >
            <span className="text-indigo-400">⚡</span> {t('linkGenerator')}
          </Link>
          <Link href="/settings" className={`flex items-center gap-3 px-4 py-3 text-neutral-300 hover:text-white hover:bg-white/5 rounded-2xl font-semibold ${FOCUS_RING_CLASS}`}>
            <span>⚙️</span> {t('profileSettings')}
          </Link>
        </nav>
      </aside>

      <main id="generator-main" className="relative z-10 px-4 sm:px-6 md:px-12 pt-10 md:ml-72">
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
                <label htmlFor="generator-amount" className="text-xs font-black uppercase tracking-widest text-neutral-300 ml-1">
                  {t('amountLabel')}
                </label>

                <div className="relative group mt-2">
                  <div className="absolute -inset-0.5 bg-gradient-to-r from-indigo-500/20 to-purple-500/20 rounded-3xl blur opacity-0 group-focus-within:opacity-100 transition" />

                  <div className="relative bg-neutral-900/50 border border-white/10 rounded-3xl p-1 shadow-2xl">
                    <input
                      id="generator-amount"
                      type="number"
                      placeholder={t('amountPlaceholder')}
                      value={form.amount}
                      onChange={(e) =>
                        setForm({ ...form, amount: e.target.value })
                      }
                      aria-invalid={Boolean(errors.amount)}
                      aria-describedby={errors.amount ? "generator-amount-error" : undefined}
                      className={`w-full bg-transparent p-6 sm:p-8 text-3xl sm:text-5xl font-black placeholder:text-neutral-500 ${FOCUS_RING_CLASS}`}
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
                            aria-pressed={recipientAssetCode === a.code}
                            aria-label={`Set recipient asset to ${a.code}`}
                            className={`
                            px-3 py-2 text-xs sm:text-sm rounded-xl transition ${FOCUS_RING_CLASS}
                            ${
                              recipientAssetCode === a.code
                                ? "bg-white text-black font-black"
                                : "text-neutral-300 hover:text-white"
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
                  <p id="generator-amount-error" role="alert" className="text-red-400 text-xs mt-2">{errors.amount}</p>
                )}
                {assetsError && (
                  <p role="alert" className="text-amber-400 text-xs mt-2">{assetsError}</p>
                )}
              </div>

              <div>
                <label htmlFor="generator-destination" className="text-xs font-black uppercase tracking-widest text-neutral-300 ml-1">
                  {t('destinationLabel')}
                </label>
                <input
                  id="generator-destination"
                  type="text"
                  placeholder={t('destinationPlaceholder')}
                  value={form.destination}
                  onChange={(e) =>
                    setForm({ ...form, destination: e.target.value })
                  }
                  aria-invalid={Boolean(errors.destination)}
                  aria-describedby={errors.destination ? "generator-destination-error" : undefined}
                  className={`w-full bg-neutral-900/30 border border-white/10 rounded-3xl p-5 font-bold mt-2 placeholder:text-neutral-400 ${FOCUS_RING_CLASS}`}
                />
                {errors.destination && (
                  <p id="generator-destination-error" role="alert" className="text-red-400 text-xs mt-2">
                    {errors.destination}
                  </p>
                )}
              </div>

              <div>
                <label htmlFor="generator-memo" className="text-xs font-black uppercase tracking-widest text-neutral-300 ml-1">
                  {t('memoLabel')}
                </label>
                <input
                  id="generator-memo"
                  type="text"
                  placeholder={t('memoPlaceholder')}
                  value={form.memo}
                  onChange={(e) => setForm({ ...form, memo: e.target.value })}
                  className={`w-full bg-neutral-900/30 border border-white/10 rounded-3xl p-5 font-bold mt-2 placeholder:text-neutral-400 ${FOCUS_RING_CLASS}`}
                />
              </div>

              <div className="rounded-3xl border border-white/10 bg-black/30 p-6 space-y-4">
                <button
                  type="button"
                  onClick={() => setAdvancedOpen((v) => !v)}
                  aria-expanded={advancedOpen}
                  aria-controls="generator-advanced-panel"
                  className={`flex w-full items-center justify-between text-left ${FOCUS_RING_CLASS}`}
                >
                  <span className="text-sm font-black uppercase tracking-widest text-indigo-300">
                    {t('advancedSettings')}
                  </span>
                  <span className="text-neutral-300 text-sm">
                    {advancedOpen ? t('hide') : t('show')} path payments
                  </span>
                </button>

                {advancedOpen && (
                  <div id="generator-advanced-panel" className="space-y-6 pt-2 border-t border-white/5">
                    <div>
                      <label htmlFor="generator-recipient-asset" className="text-xs font-bold uppercase tracking-wider text-neutral-300 mb-2 block">
                        {t('recipientAsset')}
                      </label>
                      <p className="text-sm text-neutral-300 mb-3">
                        {t('recipientAssetDescription')}
                      </p>
                      <select
                        id="generator-recipient-asset"
                        value={recipientAssetCode}
                        onChange={(e) =>
                          setRecipientAssetCode(e.target.value)
                        }
                        className={`w-full bg-neutral-900 border border-white/10 rounded-2xl p-4 font-bold ${FOCUS_RING_CLASS}`}
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
                        <p role="alert" className="text-red-400 text-xs mt-2">
                          {errors.asset}
                        </p>
                      )}
                    </div>

                    <div>
                      <p className="text-xs font-bold uppercase tracking-wider text-neutral-300 mb-2">
                        {t('allowedSourceAssets')}
                      </p>
                      <p className="text-sm text-neutral-300 mb-3">
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
                              aria-pressed={on}
                              className={`px-4 py-2 rounded-xl text-sm font-bold border transition ${
                                on
                                  ? "bg-indigo-500/30 border-indigo-400/50 text-white"
                                  : `bg-neutral-900/50 border-white/10 text-neutral-300 hover:text-white ${FOCUS_RING_CLASS}`
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
                        <h3 className="text-xs font-black uppercase tracking-widest text-neutral-300">
                          {t('pathPreview')}
                        </h3>
                        <div className="flex items-center gap-3">
                          {quoteSecondsRemaining !== null && (
                            <span
                              className={`text-xs font-mono ${
                                quoteExpired ? "text-amber-300" : "text-emerald-300"
                              }`}
                            >
                              {quoteExpired
                                ? t('quoteExpired')
                                : t('quoteExpiresIn', { seconds: quoteSecondsRemaining })}
                            </span>
                          )}
                          <button
                            type="button"
                            onClick={() => void fetchPathPreview()}
                            disabled={pathLoading}
                            className={`text-xs px-2 py-1 rounded-md border border-white/10 text-neutral-200 hover:text-white hover:bg-white/5 disabled:opacity-50 ${FOCUS_RING_CLASS}`}
                          >
                            {pathLoading ? t('fetchingEstimates') : t('refreshQuote')}
                          </button>
                        </div>
                      </div>
                      {slippageWarningText && (
                        <p
                          className={`text-xs ${
                            slippageWarningLevel === "block"
                              ? "text-red-400"
                              : "text-amber-300"
                          }`}
                        >
                          {slippageWarningText}
                        </p>
                      )}
                      {pathError && (
                        <p role="alert" className="text-amber-400 text-sm">
                          {pathErrorType === "liquidity"
                            ? t('insufficientLiquidityState')
                            : pathErrorType === "path"
                              ? t('noPathState')
                              : pathError}
                        </p>
                      )}
                      {!pathLoading &&
                        !pathError &&
                        pathData &&
                        pathData.paths.length === 0 && (
                          <p className="text-neutral-300 text-sm">
                            {t('noPathsFound', { horizonUrl: pathData.horizonUrl })}
                          </p>
                        )}
                      {!pathLoading && !pathError && !pathData && (
                        <p className="text-neutral-300 text-xs">
                          {t('pathPreviewHint')}
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
                              <div className="text-xs text-neutral-300 mt-1">
                                {t('hops', { hopCount: p.hopCount })}
                                {p.pathHops.length > 0
                                  ? ` · ${p.pathHops.join(" → ")}`
                                  : ""}
                              </div>
                              <div className="text-xs text-neutral-400 mt-1">
                                {p.rateDescription}
                              </div>
                              <div className="mt-2 rounded-lg border border-white/5 bg-white/[0.02] p-2 space-y-1">
                                <p className="text-[11px] uppercase tracking-wide text-neutral-300 font-semibold">
                                  {t('pathBreakdown')}
                                </p>
                                {getPathLegs(p).map((leg) => (
                                  <div
                                    key={`${leg.poolLabel}-${leg.fromAsset}-${leg.toAsset}`}
                                    className="flex items-center justify-between text-xs text-neutral-300"
                                  >
                                    <span>{leg.poolLabel}</span>
                                    <span className="font-mono">
                                      {leg.fromAsset} → {leg.toAsset}
                                    </span>
                                  </div>
                                ))}
                                <p className="text-xs text-neutral-300">
                                  {t('estimatedNetworkFee', {
                                    fee: ((p.hopCount + 1) * BASE_PATH_OPERATION_FEE_XLM).toFixed(5),
                                  })}
                                </p>
                              </div>
                            </li>
                          ))}
                        </ul>
                      )}
                    </div>

                    <div className="rounded-2xl border border-white/10 bg-neutral-950/60 p-4 space-y-3">
                      <div className="flex items-center justify-between">
                        <h3 className="text-xs font-black uppercase tracking-widest text-neutral-300">
                          {t('slippageTolerance')}
                        </h3>
                        <span className="text-sm font-mono text-neutral-200">
                          {slippageValue.toFixed(2)}%
                        </span>
                      </div>
                      <p className="text-xs text-neutral-300">
                        {t('slippageDescription')}
                      </p>
                      <input
                        type="range"
                        min={0.1}
                        max={5}
                        step={0.1}
                        value={slippagePct}
                        onChange={(e) => setSlippagePct(e.target.value)}
                        aria-label="Slippage percentage"
                        className={`w-full accent-indigo-400 ${FOCUS_RING_CLASS}`}
                      />
                      <div className="flex flex-wrap gap-2">
                        {["0.50", "1.00", "2.00"].map((preset) => (
                          <button
                            key={preset}
                            type="button"
                            onClick={() => setSlippagePct(preset)}
                            className={`px-3 py-1 text-xs rounded-lg border ${
                              slippagePct === preset
                                ? "border-indigo-400/60 text-indigo-200 bg-indigo-500/10"
                                : `border-white/10 text-neutral-200 ${FOCUS_RING_CLASS}`
                            }`}
                          >
                            {preset}%
                          </button>
                        ))}
                      </div>
                    </div>

                    <div className="rounded-2xl border border-white/10 bg-neutral-950/60 p-4 space-y-3">
                      <h3 className="text-xs font-black uppercase tracking-widest text-neutral-300">
                        {t('sorobanPreflight')}
                      </h3>
                      <p className="text-xs text-neutral-300">
                        {t('sorobanPreflightDescription')}
                      </p>
                      <input
                        type="text"
                        placeholder={t('sourceAccountPlaceholder')}
                        value={preflightAccount}
                        onChange={(e) => setPreflightAccount(e.target.value)}
                        className={`w-full bg-neutral-900/80 border border-white/10 rounded-xl p-3 font-mono text-sm ${FOCUS_RING_CLASS}`}
                      />
                      <button
                        type="button"
                        onClick={() => void runPreflight()}
                        disabled={preflightLoading}
                        className={`w-full py-3 rounded-xl bg-white/10 hover:bg-white/15 border border-white/10 text-sm font-bold disabled:opacity-50 ${FOCUS_RING_CLASS}`}
                      >
                        {preflightLoading
                          ? t('simulating')
                          : t('runPreflight')}
                      </button>
                      {preflightUnavailable && (
                        <p role="alert" className="text-amber-400 text-sm">
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
              type="button"
              onClick={handleSubmit}
              disabled={loading}
              className={`w-full py-6 bg-white text-black text-3xl font-black rounded-3xl hover:bg-neutral-200 active:scale-95 transition disabled:opacity-60 ${FOCUS_RING_CLASS}`}
            >
              {loading ? "Generating…" : "Generate Payment Link"}
            </button>
            {error && (
              <p role="alert" className="text-red-400 text-sm text-center">{error}</p>
            )}
          </div>

          <div className="space-y-12">
            <div className="w-full max-w-sm mx-auto">
              <QRPreview value={linkData} />
            </div>

            <div className="space-y-4 p-8 rounded-3xl bg-black/40 border border-white/5 backdrop-blur-xl">
              <label className="text-[10px] font-black uppercase tracking-widest text-neutral-300">
                Canonical query (from API)
              </label>

              <div className="bg-neutral-900 border border-white/5 p-4 rounded-xl font-mono text-neutral-200 text-xs break-all min-h-[3rem]">
                {canonicalPreview ?? (
                  <span className="text-neutral-400 italic">
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
                aria-label="Copy canonical query parameters"
                className={`w-full py-3 bg-white/10 text-white rounded-xl border border-white/5 text-xs uppercase tracking-widest hover:bg-white/15 disabled:opacity-40 disabled:cursor-not-allowed ${FOCUS_RING_CLASS}`}
              >
                Copy canonical params
              </button>
            </div>
          </div>
        </div>

        <section className="mt-20 max-w-7xl space-y-8">
          <div className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
            <div>
              <p className="text-xs font-black uppercase tracking-widest text-indigo-300">
                Bulk Invoicing v2
              </p>
              <h2 className="text-3xl font-black text-white mt-2">
                Templates, saved customers, and preview before generation
              </h2>
              <p className="text-neutral-400 mt-3 max-w-3xl">
                Reuse one invoice template across your customer directory, then generate the final payment links from the same preview payload.
              </p>
            </div>
            <button
              type="button"
              onClick={() => setBulkResult(null)}
              className={`rounded-xl border border-white/10 px-4 py-2 text-sm font-semibold text-neutral-200 hover:bg-white/5 ${FOCUS_RING_CLASS}`}
            >
              Clear generated results
            </button>
          </div>

          <div className="grid gap-8 xl:grid-cols-[1.05fr_0.95fr]">
            <div className="space-y-8">
              <div className="rounded-3xl border border-white/10 bg-black/30 p-6">
                <div className="flex items-center justify-between gap-4 mb-5">
                  <div>
                    <h3 className="text-xl font-bold text-white">Invoice templates</h3>
                    <p className="text-sm text-neutral-400">Line items, tax, notes, and destination asset.</p>
                  </div>
                  <button
                    type="button"
                    onClick={resetTemplateForm}
                    className={`rounded-xl border border-white/10 px-3 py-2 text-xs font-semibold text-neutral-200 hover:bg-white/5 ${FOCUS_RING_CLASS}`}
                  >
                    New template
                  </button>
                </div>

                <div className="grid gap-3 md:grid-cols-2 mb-5">
                  <input
                    type="text"
                    value={templateForm.name}
                    onChange={(event) =>
                      setTemplateForm((current) => ({ ...current, name: event.target.value }))
                    }
                    placeholder="Template name"
                    className={`rounded-2xl border border-white/10 bg-neutral-900/60 px-4 py-3 text-sm text-white ${FOCUS_RING_CLASS}`}
                  />
                  <input
                    type="text"
                    value={templateForm.asset}
                    onChange={(event) =>
                      setTemplateForm((current) => ({ ...current, asset: event.target.value.toUpperCase() }))
                    }
                    placeholder="Asset code"
                    className={`rounded-2xl border border-white/10 bg-neutral-900/60 px-4 py-3 text-sm text-white ${FOCUS_RING_CLASS}`}
                  />
                  <input
                    type="number"
                    value={templateForm.taxRate}
                    onChange={(event) =>
                      setTemplateForm((current) => ({ ...current, taxRate: event.target.value }))
                    }
                    placeholder="Tax %"
                    className={`rounded-2xl border border-white/10 bg-neutral-900/60 px-4 py-3 text-sm text-white ${FOCUS_RING_CLASS}`}
                  />
                  <input
                    type="text"
                    value={templateForm.notes}
                    onChange={(event) =>
                      setTemplateForm((current) => ({ ...current, notes: event.target.value }))
                    }
                    placeholder="Notes"
                    className={`rounded-2xl border border-white/10 bg-neutral-900/60 px-4 py-3 text-sm text-white ${FOCUS_RING_CLASS}`}
                  />
                </div>

                <textarea
                  value={templateForm.lineItemsText}
                  onChange={(event) =>
                    setTemplateForm((current) => ({ ...current, lineItemsText: event.target.value }))
                  }
                  rows={5}
                  placeholder="Description|Qty|Unit Price"
                  className={`w-full rounded-2xl border border-white/10 bg-neutral-900/60 px-4 py-3 text-sm text-white ${FOCUS_RING_CLASS}`}
                />
                <p className="mt-2 text-xs text-neutral-500">
                  One line item per row using <span className="font-mono">Description|Qty|Unit Price</span>
                </p>

                <div className="flex flex-wrap gap-3 mt-5">
                  <button
                    type="button"
                    onClick={saveTemplate}
                    className={`rounded-2xl bg-white px-4 py-3 text-sm font-bold text-black hover:bg-neutral-200 ${FOCUS_RING_CLASS}`}
                  >
                    {editingTemplateId ? "Update template" : "Save template"}
                  </button>
                  <select
                    value={selectedTemplateId}
                    onChange={(event) => setSelectedTemplateId(event.target.value)}
                    className={`rounded-2xl border border-white/10 bg-neutral-900/60 px-4 py-3 text-sm text-white ${FOCUS_RING_CLASS}`}
                  >
                    {templates.map((template) => (
                      <option key={template.id} value={template.id}>
                        {template.name}
                      </option>
                    ))}
                  </select>
                </div>

                <div className="mt-6 space-y-3">
                  {templates.map((template) => (
                    <div
                      key={template.id}
                      className={`rounded-2xl border px-4 py-4 ${
                        selectedTemplateId === template.id
                          ? "border-indigo-400/60 bg-indigo-500/10"
                          : "border-white/10 bg-white/[0.03]"
                      }`}
                    >
                      <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
                        <div>
                          <p className="font-semibold text-white">{template.name}</p>
                          <p className="text-sm text-neutral-400">
                            {template.asset} • subtotal {formatCurrencyAmount(calculateTemplateSubtotal(template))} • tax {formatCurrencyAmount(calculateTemplateTax(template))} • total {formatCurrencyAmount(calculateTemplateTotal(template))}
                          </p>
                        </div>
                        <div className="flex gap-2">
                          <button
                            type="button"
                            onClick={() => editTemplate(template)}
                            className={`rounded-xl border border-white/10 px-3 py-2 text-xs font-semibold text-neutral-200 hover:bg-white/5 ${FOCUS_RING_CLASS}`}
                          >
                            Edit
                          </button>
                          <button
                            type="button"
                            onClick={() => deleteTemplate(template.id)}
                            className={`rounded-xl border border-red-500/20 px-3 py-2 text-xs font-semibold text-red-200 hover:bg-red-500/10 ${FOCUS_RING_CLASS}`}
                          >
                            Delete
                          </button>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div className="rounded-3xl border border-white/10 bg-black/30 p-6">
                <div className="flex items-center justify-between gap-4 mb-5">
                  <div>
                    <h3 className="text-xl font-bold text-white">Saved customers</h3>
                    <p className="text-sm text-neutral-400">Store contact info plus username or Stellar destination.</p>
                  </div>
                  <button
                    type="button"
                    onClick={resetCustomerForm}
                    className={`rounded-xl border border-white/10 px-3 py-2 text-xs font-semibold text-neutral-200 hover:bg-white/5 ${FOCUS_RING_CLASS}`}
                  >
                    New customer
                  </button>
                </div>

                <div className="grid gap-3 md:grid-cols-2 mb-5">
                  <input
                    type="text"
                    value={customerForm.name}
                    onChange={(event) =>
                      setCustomerForm((current) => ({ ...current, name: event.target.value }))
                    }
                    placeholder="Customer name"
                    className={`rounded-2xl border border-white/10 bg-neutral-900/60 px-4 py-3 text-sm text-white ${FOCUS_RING_CLASS}`}
                  />
                  <input
                    type="email"
                    value={customerForm.email}
                    onChange={(event) =>
                      setCustomerForm((current) => ({ ...current, email: event.target.value }))
                    }
                    placeholder="Email"
                    className={`rounded-2xl border border-white/10 bg-neutral-900/60 px-4 py-3 text-sm text-white ${FOCUS_RING_CLASS}`}
                  />
                  <input
                    type="text"
                    value={customerForm.address}
                    onChange={(event) =>
                      setCustomerForm((current) => ({ ...current, address: event.target.value }))
                    }
                    placeholder="Stellar address"
                    className={`rounded-2xl border border-white/10 bg-neutral-900/60 px-4 py-3 text-sm text-white ${FOCUS_RING_CLASS}`}
                  />
                  <input
                    type="text"
                    value={customerForm.username}
                    onChange={(event) =>
                      setCustomerForm((current) => ({ ...current, username: event.target.value }))
                    }
                    placeholder="Username"
                    className={`rounded-2xl border border-white/10 bg-neutral-900/60 px-4 py-3 text-sm text-white ${FOCUS_RING_CLASS}`}
                  />
                </div>

                <button
                  type="button"
                  onClick={saveCustomer}
                  className={`rounded-2xl bg-white px-4 py-3 text-sm font-bold text-black hover:bg-neutral-200 ${FOCUS_RING_CLASS}`}
                >
                  {editingCustomerId ? "Update customer" : "Save customer"}
                </button>

                <div className="mt-6 space-y-3">
                  {customers.map((customer) => (
                    <div key={customer.id} className="rounded-2xl border border-white/10 bg-white/[0.03] px-4 py-4">
                      <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
                        <label className="flex items-start gap-3">
                          <input
                            type="checkbox"
                            checked={selectedCustomerIds.includes(customer.id)}
                            onChange={() => toggleCustomerSelection(customer.id)}
                            className="mt-1 h-4 w-4"
                          />
                          <div>
                            <p className="font-semibold text-white">{customer.name}</p>
                            <p className="text-sm text-neutral-400">{customer.email}</p>
                            <p className="text-xs text-neutral-500">
                              {customer.username || customer.address || "Missing payment route"}
                            </p>
                          </div>
                        </label>
                        <div className="flex gap-2">
                          <button
                            type="button"
                            onClick={() => editCustomer(customer)}
                            className={`rounded-xl border border-white/10 px-3 py-2 text-xs font-semibold text-neutral-200 hover:bg-white/5 ${FOCUS_RING_CLASS}`}
                          >
                            Edit
                          </button>
                          <button
                            type="button"
                            onClick={() => deleteCustomer(customer.id)}
                            className={`rounded-xl border border-red-500/20 px-3 py-2 text-xs font-semibold text-red-200 hover:bg-red-500/10 ${FOCUS_RING_CLASS}`}
                          >
                            Delete
                          </button>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            <div className="space-y-8">
              <div className="rounded-3xl border border-white/10 bg-black/30 p-6">
                <div className="flex items-center justify-between gap-3 mb-4">
                  <div>
                    <h3 className="text-xl font-bold text-white">Preview</h3>
                    <p className="text-sm text-neutral-400">These rows are transformed directly into the bulk API payload.</p>
                  </div>
                  <button
                    type="button"
                    onClick={() => void generateBulkInvoices()}
                    disabled={bulkLoading}
                    className={`rounded-2xl bg-white px-4 py-3 text-sm font-bold text-black hover:bg-neutral-200 disabled:opacity-50 ${FOCUS_RING_CLASS}`}
                  >
                    {bulkLoading ? "Generating..." : "Generate invoices"}
                  </button>
                </div>

                {bulkError && (
                  <p className="mb-4 rounded-md border border-amber-300/30 bg-amber-500/10 px-3 py-2 text-sm text-amber-200">
                    {bulkError}
                  </p>
                )}

                <div className="space-y-4">
                  {invoicePreviewRows.map((row) => (
                    <div key={row.id} className="rounded-2xl border border-white/10 bg-neutral-950/50 p-4">
                      <div className="flex flex-col gap-2 md:flex-row md:items-start md:justify-between">
                        <div>
                          <p className="font-semibold text-white">{row.customerName}</p>
                          <p className="text-sm text-neutral-400">{row.email}</p>
                          <p className="text-xs text-neutral-500">
                            {row.username ?? row.destination ?? "Missing payment route"}
                          </p>
                        </div>
                        <div className="text-right">
                          <p className="text-lg font-black text-white">
                            {formatCurrencyAmount(row.total)} {row.asset}
                          </p>
                          <p className="text-xs text-neutral-500">{row.referenceId}</p>
                        </div>
                      </div>
                      <div className="mt-4 space-y-2">
                        {row.lineItems.map((item) => (
                          <div key={item.id} className="flex items-center justify-between text-sm text-neutral-300">
                            <span>{item.description}</span>
                            <span className="font-mono">
                              {item.quantity} × {formatCurrencyAmount(item.unitPrice)}
                            </span>
                          </div>
                        ))}
                        <div className="border-t border-white/10 pt-2 text-sm text-neutral-300">
                          <div className="flex items-center justify-between">
                            <span>Subtotal</span>
                            <span>{formatCurrencyAmount(row.subtotal)}</span>
                          </div>
                          <div className="flex items-center justify-between">
                            <span>Tax</span>
                            <span>{formatCurrencyAmount(row.taxAmount)}</span>
                          </div>
                          <div className="flex items-center justify-between font-semibold text-white">
                            <span>Total</span>
                            <span>{formatCurrencyAmount(row.total)}</span>
                          </div>
                        </div>
                        <div className="rounded-xl border border-white/10 bg-white/[0.03] px-3 py-2 text-xs text-neutral-300">
                          <p className="font-semibold text-neutral-200">Generated memo</p>
                          <p>{row.memo}</p>
                        </div>
                        {row.notes && (
                          <div className="rounded-xl border border-white/10 bg-white/[0.03] px-3 py-2 text-xs text-neutral-300">
                            <p className="font-semibold text-neutral-200">Notes</p>
                            <p>{row.notes}</p>
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                  {invoicePreviewRows.length === 0 && (
                    <p className="rounded-2xl border border-dashed border-white/10 px-4 py-8 text-center text-sm text-neutral-400">
                      Select a template and at least one saved customer to build the preview.
                    </p>
                  )}
                </div>
              </div>

              <div className="rounded-3xl border border-white/10 bg-black/30 p-6">
                <h3 className="text-xl font-bold text-white mb-4">Generated output</h3>
                <div className="rounded-2xl border border-white/10 bg-neutral-950/60 p-4 text-xs text-neutral-300">
                  <pre className="overflow-x-auto whitespace-pre-wrap">
                    {JSON.stringify({ links: previewGenerationPayload }, null, 2)}
                  </pre>
                </div>
                {bulkResult && (
                  <div className="mt-5 space-y-3">
                    {bulkResult.links.map((link) => (
                      <div key={link.id} className="rounded-2xl border border-white/10 bg-white/[0.03] px-4 py-4">
                        <p className="font-semibold text-white">{link.referenceId ?? link.id}</p>
                        <p className="mt-1 break-all text-xs text-neutral-400">{link.url}</p>
                        <p className="mt-2 text-xs text-neutral-500">{link.canonical}</p>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        </section>
      </main>
    </div>
  );
}
