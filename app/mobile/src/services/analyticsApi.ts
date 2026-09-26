import { createClientForEnvironment, ENVIRONMENTS, DEFAULT_ENVIRONMENT, type EnvironmentId } from "./quickexApi";
import * as FileSystem from "expo-file-system";
import * as Sharing from "expo-sharing";

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
    successfulTx: number;
    failedTx: number;
    conversionRate: number;
    refundCount: number;
    refundVolume: number;
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

function labelForPeriod(period: string): string {
  if (/^\d{4}-\d{2}-\d{2}$/.test(period)) {
    const d = new Date(`${period}T00:00:00.000Z`);
    return d.toLocaleDateString("en-US", { month: "numeric", day: "numeric" });
  }

  if (/^\d{4}-\d{2}$/.test(period)) {
    const [year, month] = period.split("-");
    const d = new Date(`${year}-${month}-01T00:00:00.000Z`);
    return d.toLocaleDateString("en-US", { month: "short" });
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
      successfulTx: report.summary.successfulTransactions,
      failedTx: report.summary.failedTransactions,
      conversionRate: report.summary.conversionRate ?? (report.summary.totalTransactions > 0 ? (report.summary.successfulTransactions / report.summary.totalTransactions) * 100 : 100),
      refundCount: report.summary.failedTransactions,
      refundVolume: 0,
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
      successfulTx: 0,
      failedTx: 0,
      conversionRate: 100,
      refundCount: 0,
      refundVolume: 0,
    },
  };
}

export async function fetchAnalytics(
  publicKey: string,
  range: DateRange = "30d",
  environmentId: EnvironmentId = DEFAULT_ENVIRONMENT,
): Promise<AnalyticsData> {
  if (analyticsCache[range]) {
    return Promise.resolve(analyticsCache[range] as AnalyticsData);
  }

  const client = createClientForEnvironment(environmentId);
  const { startDate, endDate, interval } = rangeToWindow(range);

  try {
    const { data, response } = await client.GET("/analytics/report", {
      params: {
        query: {
          publicKey,
          startDate,
          endDate,
          interval,
        },
      },
    });

    if (!response.ok || !data) {
      throw new Error(`Analytics request failed with status ${response.status}`);
    }

    const report = data as ApiReport;
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
  publicKey: string,
  range: DateRange = "30d",
  format: "csv" | "pdf" = "csv",
  reportType: "tax" | "accounting" = "accounting",
  environmentId: EnvironmentId = DEFAULT_ENVIRONMENT,
): Promise<void> {
  const { startDate, endDate, interval } = rangeToWindow(range);
  const baseUrl = ENVIRONMENTS[environmentId].apiUrl;

  // Use fetch directly to handle binary response properly
  const url = new URL(`${baseUrl}/analytics/export`);
  url.searchParams.set("publicKey", publicKey);
  url.searchParams.set("startDate", startDate);
  url.searchParams.set("endDate", endDate);
  url.searchParams.set("interval", interval);
  url.searchParams.set("format", format);
  url.searchParams.set("reportType", reportType);

  const response = await fetch(url.toString(), {
    method: "GET",
  });

  if (!response.ok) {
    throw new Error(`Export request failed with status ${response.status}`);
  }

  // Get the response as text (CSV) or handle binary (PDF)
  let fileContent: string;
  
  if (format === "csv") {
    fileContent = await response.text();
  } else {
    // For PDF, we need to handle binary data
    const arrayBuffer = await response.arrayBuffer();
    fileContent = arrayBufferToBase64(arrayBuffer);
  }

  // Create a temporary file
  const fileName = `quickex-analytics-report.${format}`;
  const fileUri = FileSystem.cacheDirectory + fileName;
  
  await FileSystem.writeAsStringAsync(fileUri, fileContent, {
    encoding: format === "csv" ? "utf8" : "base64",
  });

  // Share the file using platform share sheet
  if (await Sharing.isAvailableAsync()) {
    await Sharing.shareAsync(fileUri, {
      mimeType: format === "csv" ? "text/csv" : "application/pdf",
      dialogTitle: "Export Analytics Report",
    });
  } else {
    throw new Error("Sharing is not available on this platform");
  }

  // Clean up the temporary file
  await FileSystem.deleteAsync(fileUri, { idempotent: true });
}

function arrayBufferToBase64(arrayBuffer: ArrayBuffer): string {
  let binary = "";
  const bytes = new Uint8Array(arrayBuffer);
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

export function clearAnalyticsCache(): void {
  Object.keys(analyticsCache).forEach((key) => {
    delete analyticsCache[key as DateRange];
  });
}