import i18n from 'i18next';

/**
 * analyticsApi.ts
 *
 * Mock data layer for the analytics dashboard (Issue #175).
 * Designed to be a drop-in replacement once the Wave 3 backend
 * analytics endpoints are live. Simply swap mockFetch() calls
 * for real fetch() calls to the same endpoint shape.
 */

export type DateRange = "24h" | "7d" | "30d" | "all";

export interface VolumeDataPoint {
  date: string; // ISO-8601 label
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

const analyticsCache: Partial<Record<DateRange, AnalyticsData>> = {};

// ─── helpers ─────────────────────────────────────────────────────────────────

function randomBetween(lo: number, hi: number) {
  return Math.round(lo + Math.random() * (hi - lo));
}

function buildSeries(points: number, labelFn: (i: number) => string): VolumeDataPoint[] {
  return Array.from({ length: points }, (_, i) => {
    const usdc = randomBetween(200, 1800);
    const xlm = randomBetween(80, 600);
    return { date: labelFn(i), volumeUSDC: usdc, volumeXLM: xlm, total: usdc + xlm };
  });
}

function toTx(series: VolumeDataPoint[]): TxCountDataPoint[] {
  return series.map((d) => ({ date: d.date, count: randomBetween(4, 42) }));
}

// ─── data factories ───────────────────────────────────────────────────────────

const now = new Date();

function makeData(range: DateRange): Omit<AnalyticsData, "summary"> {
  let volume: VolumeDataPoint[];

  if (range === "24h") {
    volume = buildSeries(24, (i) => `${String(i).padStart(2, "0")}:00`);
  } else if (range === "7d") {
    volume = buildSeries(7, (i) => {
      const d = new Date(now);
      d.setDate(d.getDate() - (6 - i));
      return d.toLocaleDateString(i18n.language || "en", { weekday: "short" });
    });
  } else if (range === "30d") {
    volume = buildSeries(30, (i) => {
      const d = new Date(now);
      d.setDate(d.getDate() - (29 - i));
      return d.toLocaleDateString(i18n.language || "en", {
        month: "numeric",
        day: "numeric",
      });
    });
  } else {
    // all time — 12 months
    volume = buildSeries(12, (i) => {
      const d = new Date(now);
      d.setMonth(d.getMonth() - (11 - i));
      return d.toLocaleDateString(i18n.language || "en", { month: "short" });
    });
  }

  return {
    volume,
    txCount: toTx(volume),
    assetDist: [
      { name: "USDC", value: randomBetween(48, 62), color: "#6366f1" },
      { name: "XLM",  value: randomBetween(25, 35), color: "#8b5cf6" },
      { name: "Other", value: randomBetween(5, 15), color: "#334155" },
    ],
  };
}

// ─── public API ───────────────────────────────────────────────────────────────

export async function fetchAnalytics(range: DateRange): Promise<AnalyticsData> {
  if (analyticsCache[range]) {
    return Promise.resolve(analyticsCache[range] as AnalyticsData);
  }

  // Simulates network latency; replace body with real fetch when backend is ready:
  // const res = await fetch(`/api/analytics?range=${range}`);
  // const json = await res.json();
  // return json as AnalyticsData;
  await new Promise((r) => setTimeout(r, 600));

  const { volume, txCount, assetDist } = makeData(range);

  const totalVolume = volume.reduce((s, d) => s + d.total, 0);
  const totalTx = txCount.reduce((s, d) => s + d.count, 0);

  const result = {
    volume,
    txCount,
    assetDist,
    summary: {
      totalVolume,
      totalTx,
      avgTxSize: Math.round(totalVolume / Math.max(totalTx, 1)),
      changeVolumePercent: parseFloat((Math.random() * 40 - 10).toFixed(1)),
    },
  };

  analyticsCache[range] = result;
  return result;
}
