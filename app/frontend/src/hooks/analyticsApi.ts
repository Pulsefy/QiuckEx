import i18n from "i18next";
import { getQuickexApiBase } from "@/lib/api";

export type DateRange = "24h" | "7d" | "30d" | "all";

export interface VolumeDataPoint {
  date: string;
  volumeUSDC: number;
  volumeXLM: number;
  total: number;
}

export interface TxCountDataPoint {
  date: string;
  count: number;
}

export interface AssetSlice {
  name: string;
  value: number;
  color: string;
}

export interface AnalyticsData {
  volume: VolumeDataPoint[];
  txCount: TxCountDataPoint[];
  assetDist: AssetSlice[];
  summary: {
    totalVolume: number;
    totalTx: number;
    avgTxSize: number;
    changeVolumePercent: number;
  };
}

type ApiTimeSeriesItem = {
  period: string;
  transactionCount: number;
  successfulTransactions: number;
  volumeUsd: number;
  assetVolumes?: Record<string, number>;
};

type ApiReport = {
  summary: {
    totalTransactions: number;
    successfulTransactions: number;
    failedTransactions: number;
    conversionRate: number;
    totalVolumeUsd: number;
    averageTransactionUsd: number;
  };
  assetDistribution: Array<{
    asset: string;
    volumeUsd: number;
    percentage: number;
    transactionCount: number;
  }>;
  timeSeries: ApiTimeSeriesItem[];
};

const analyticsCache: Partial<Record<DateRange, AnalyticsData>> = {};
const DEFAULT_PUBLIC_KEY =
  "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const PUBLIC_KEY_REGEX = /^G[A-Z2-7]{55}$/;
const PUBLIC_KEY_STORAGE_CANDIDATES = [
  "quickex.publicKey",
  "quickex.walletPublicKey",
  "walletPublicKey",
  "publicKey",
];
const ASSET_COLORS: Record<string, string> = {
  USDC: "#6366f1",
  XLM: "#8b5cf6",
};

function rangeToWindow(range: DateRange): {
  startDate: string;
  endDate: string;
  interval: "daily" | "weekly" | "monthly";
} {
  const end = new Date();
  const start = new Date(end);
  let interval: "daily" | "weekly" | "monthly" = "daily";

  if (range === "24h") {
    start.setHours(start.getHours() - 24);
    interval = "daily";
  } else if (range === "7d") {
    start.setDate(start.getDate() - 7);
    interval = "daily";
  } else if (range === "30d") {
    start.setDate(start.getDate() - 30);
    interval = "daily";
  } else {
    start.setFullYear(start.getFullYear() - 1);
    interval = "monthly";
  }

  return {
    startDate: start.toISOString(),
    endDate: end.toISOString(),
    interval,
  };
}

function resolveAnalyticsPublicKey(): string {
  if (typeof window !== "undefined") {
    for (const key of PUBLIC_KEY_STORAGE_CANDIDATES) {
      const value = window.localStorage.getItem(key)?.trim();
      if (value && PUBLIC_KEY_REGEX.test(value)) {
        return value;
      }
    }
  }

  const fromEnv = process.env.NEXT_PUBLIC_QUICKEX_ANALYTICS_PUBLIC_KEY?.trim();
  if (fromEnv && PUBLIC_KEY_REGEX.test(fromEnv)) {
    return fromEnv;
  }

  return DEFAULT_PUBLIC_KEY;
}

function labelForPeriod(period: string): string {
  const locale = i18n.language || "en";

  if (/^\d{4}-\d{2}-\d{2}$/.test(period)) {
    const d = new Date(`${period}T00:00:00.000Z`);
    return d.toLocaleDateString(locale, { month: "numeric", day: "numeric" });
  }

  if (/^\d{4}-\d{2}$/.test(period)) {
    const [year, month] = period.split("-");
    const d = new Date(`${year}-${month}-01T00:00:00.000Z`);
    return d.toLocaleDateString(locale, { month: "short" });
  }

  if (/^\d{4}-W\d{2}$/.test(period)) {
    const [, week] = period.split("-W");
    return `W${week}`;
  }

  return period;
}

function toUiModel(report: ApiReport): AnalyticsData {
  const volume = report.timeSeries.map((item) => {
    const volumeUSDC = item.assetVolumes?.USDC ?? 0;
    const volumeXLM = item.assetVolumes?.XLM ?? 0;
    return {
      date: labelForPeriod(item.period),
      volumeUSDC,
      volumeXLM,
      total: item.volumeUsd,
    };
  });

  const txCount: TxCountDataPoint[] = report.timeSeries.map((item) => ({
    date: labelForPeriod(item.period),
    count: item.transactionCount,
  }));

  const assetDist: AssetSlice[] = report.assetDistribution
    .slice()
    .sort((a, b) => b.volumeUsd - a.volumeUsd)
    .map((item, index) => ({
      name: item.asset,
      value: Number(item.percentage.toFixed(2)),
      color: ASSET_COLORS[item.asset] ?? (index % 2 === 0 ? "#334155" : "#64748b"),
    }));

  return {
    volume,
    txCount,
    assetDist,
    summary: {
      totalVolume: report.summary.totalVolumeUsd,
      totalTx: report.summary.totalTransactions,
      avgTxSize: report.summary.averageTransactionUsd,
      changeVolumePercent: 0,
    },
  };
}

function fallbackEmpty(): AnalyticsData {
  return {
    volume: [],
    txCount: [],
    assetDist: [],
    summary: {
      totalVolume: 0,
      totalTx: 0,
      avgTxSize: 0,
      changeVolumePercent: 0,
    },
  };
}

export async function fetchAnalytics(range: DateRange): Promise<AnalyticsData> {
  if (analyticsCache[range]) {
    return Promise.resolve(analyticsCache[range] as AnalyticsData);
  }

  const publicKey = resolveAnalyticsPublicKey();
  const { startDate, endDate, interval } = rangeToWindow(range);
  const url = new URL(`${getQuickexApiBase()}/analytics/report`);
  url.searchParams.set("publicKey", publicKey);
  url.searchParams.set("startDate", startDate);
  url.searchParams.set("endDate", endDate);
  url.searchParams.set("interval", interval);

  try {
    const res = await fetch(url.toString(), { method: "GET" });
    if (!res.ok) {
      throw new Error(`Analytics request failed with status ${res.status}`);
    }
    const report = (await res.json()) as ApiReport;
    const parsed = toUiModel(report);
    analyticsCache[range] = parsed;
    return parsed;
  } catch (error) {
    console.warn("Falling back to empty analytics data:", error);
    const empty = fallbackEmpty();
    analyticsCache[range] = empty;
    return empty;
  }
}

export async function exportAnalyticsReport(
  range: DateRange,
  format: "csv" | "pdf",
  reportType: "tax" | "accounting" = "accounting",
): Promise<void> {
  const publicKey = resolveAnalyticsPublicKey();
  const { startDate, endDate, interval } = rangeToWindow(range);
  const url = new URL(`${getQuickexApiBase()}/analytics/export`);
  url.searchParams.set("publicKey", publicKey);
  url.searchParams.set("startDate", startDate);
  url.searchParams.set("endDate", endDate);
  url.searchParams.set("interval", interval);
  url.searchParams.set("format", format);
  url.searchParams.set("reportType", reportType);

  const res = await fetch(url.toString(), { method: "GET" });
  if (!res.ok) {
    throw new Error(`Export request failed with status ${res.status}`);
  }

  const blob = await res.blob();
  const disposition = res.headers.get("Content-Disposition");
  const fallbackName = `quickex-analytics-report.${format}`;
  const fileName = parseFilename(disposition) ?? fallbackName;
  const objectUrl = window.URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = objectUrl;
  link.download = fileName;
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.URL.revokeObjectURL(objectUrl);
}

function parseFilename(disposition: string | null): string | null {
  if (!disposition) return null;
  const match = /filename="?([^"]+)"?/i.exec(disposition);
  return match?.[1] ?? null;
}
