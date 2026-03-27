"use client";

/**
 * AnalyticsDashboard.tsx
 *
 * Interactive analytics dashboard for QuickEx (Issue #175).
 * Charts: Area (volume), Line (tx count), Donut (asset distribution).
 * Fully responsive and themed to QuickEx dark-glass aesthetic.
 */

import { useEffect, useState, useCallback } from "react";
import {
  AreaChart,
  Area,
  LineChart,
  Line,
  PieChart,
  Pie,
  Cell,
  Tooltip,
  Legend,
  XAxis,
  YAxis,
  CartesianGrid,
  ResponsiveContainer,
} from "recharts";
import type {
  ValueType,
  NameType,
} from "recharts/types/component/DefaultTooltipContent";
import {
  fetchAnalytics,
  type DateRange,
  type AnalyticsData,
} from "@/hooks/analyticsApi";

// ─── Date-range filter ────────────────────────────────────────────────────────

const RANGES: { label: string; value: DateRange }[] = [
  { label: "24h", value: "24h" },
  { label: "7d", value: "7d" },
  { label: "30d", value: "30d" },
  { label: "All Time", value: "all" },
];

function DateRangeFilter({
  active,
  onChange,
}: {
  active: DateRange;
  onChange: (r: DateRange) => void;
}) {
  return (
    <div className="inline-flex gap-1 p-1 rounded-xl bg-white/5 border border-white/5">
      {RANGES.map((r) => (
        <button
          key={r.value}
          id={`analytics-range-${r.value}`}
          onClick={() => onChange(r.value)}
          className={`px-3 py-1.5 text-xs font-black rounded-lg transition-all ${
            active === r.value
              ? "bg-indigo-500 text-white shadow-lg shadow-indigo-500/20"
              : "text-neutral-500 hover:text-white hover:bg-white/5"
          }`}
        >
          {r.label}
        </button>
      ))}
    </div>
  );
}

// ─── Shared tooltip styles ────────────────────────────────────────────────────

const tooltipStyle = {
  contentStyle: {
    background: "rgba(10,10,20,0.9)",
    border: "1px solid rgba(255,255,255,0.06)",
    borderRadius: "12px",
    color: "#fff",
    fontSize: "12px",
    boxShadow: "0 8px 32px rgba(0,0,0,0.4)",
  },
  labelStyle: { color: "#6366f1", fontWeight: 800 },
  cursor: { stroke: "rgba(99,102,241,0.3)", strokeWidth: 2 },
};

// ─── Skeleton loader ──────────────────────────────────────────────────────────

function ChartSkeleton() {
  return (
    <div className="animate-pulse flex flex-col gap-3 h-full">
      <div className="h-4 bg-white/5 rounded w-1/3" />
      <div className="flex-1 bg-white/[0.03] rounded-2xl" />
    </div>
  );
}

// ─── Stat card used in the summary row ───────────────────────────────────────

function StatCard({
  label,
  value,
  change,
}: {
  label: string;
  value: string;
  change?: number;
}) {
  const positive = (change ?? 0) >= 0;
  return (
    <div className="p-5 rounded-2xl bg-white/[0.03] border border-white/5 flex flex-col gap-1">
      <p className="text-[10px] font-black uppercase tracking-widest text-neutral-500">
        {label}
      </p>
      <p className="text-2xl font-black">{value}</p>
      {change !== undefined && (
        <span
          className={`text-[11px] font-black px-2 py-0.5 w-fit rounded-lg ${
            positive
              ? "text-emerald-400 bg-emerald-400/10"
              : "text-red-400 bg-red-400/10"
          }`}
        >
          {positive ? "+" : ""}
          {change}%
        </span>
      )}
    </div>
  );
}

// ─── Custom Donut label ───────────────────────────────────────────────────────

function DonutLabel({
  cx,
  cy,
  total,
}: {
  cx: number;
  cy: number;
  total: number;
}) {
  return (
    <>
      <text
        x={cx}
        y={cy - 8}
        textAnchor="middle"
        fill="#6366f1"
        style={{ fontSize: 11, fontWeight: 900, letterSpacing: 2 }}
      >
        TOTAL
      </text>
      <text
        x={cx}
        y={cy + 12}
        textAnchor="middle"
        fill="#fff"
        style={{ fontSize: 18, fontWeight: 900 }}
      >
        {total}%
      </text>
    </>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────

export default function AnalyticsDashboard() {
  const [range, setRange] = useState<DateRange>("30d");
  const [data, setData] = useState<AnalyticsData | null>(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback((r: DateRange) => {
    setLoading(true);
    fetchAnalytics(r).then((d) => {
      setData(d);
      setLoading(false);
    });
  }, []);

  useEffect(() => {
    load(range);
  }, [range, load]);

  const { summary, volume, txCount, assetDist } = data ?? {
    summary: null,
    volume: [],
    txCount: [],
    assetDist: [],
  };

  const fmt = (n: number) =>
    n >= 1000 ? `$${(n / 1000).toFixed(1)}k` : `$${n}`;

  return (
    <section
      id="analytics-dashboard"
      className="rounded-3xl bg-black/40 border border-white/5 backdrop-blur-2xl shadow-2xl overflow-hidden"
    >
      {/* ── Header ── */}
      <div className="p-6 sm:p-10 border-b border-white/5 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl sm:text-2xl font-black mb-1">
            Analytics Overview
          </h2>
          <p className="text-xs sm:text-sm text-neutral-500">
            Payment volume, transaction counts &amp; asset distribution
          </p>
        </div>
        <DateRangeFilter active={range} onChange={setRange} />
      </div>

      <div className="p-6 sm:p-10 space-y-10">
        {/* ── Summary stats ── */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {loading || !summary ? (
            Array.from({ length: 4 }).map((_, i) => (
              <div
                key={i}
                className="animate-pulse h-24 rounded-2xl bg-white/[0.03]"
              />
            ))
          ) : (
            <>
              <StatCard
                label="Total Volume"
                value={fmt(summary.totalVolume)}
                change={summary.changeVolumePercent}
              />
              <StatCard
                label="Transactions"
                value={summary.totalTx.toLocaleString()}
              />
              <StatCard
                label="Avg Tx Size"
                value={fmt(summary.avgTxSize)}
              />
              <StatCard
                label="Top Asset"
                value={
                  assetDist.length > 0
                    ? `${assetDist.sort((a, b) => b.value - a.value)[0].name}`
                    : "—"
                }
              />
            </>
          )}
        </div>

        {/* ── Area Chart: Payment Volume ── */}
        <div>
          <h3 className="text-sm font-black uppercase tracking-widest text-neutral-500 mb-5">
            Payment Volume
          </h3>
          <div className="h-64">
            {loading ? (
              <ChartSkeleton />
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart
                  data={volume}
                  margin={{ top: 4, right: 4, left: -20, bottom: 0 }}
                >
                  <defs>
                    <linearGradient id="gUsdc" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#6366f1" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#6366f1" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="gXlm" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#8b5cf6" stopOpacity={0.2} />
                      <stop offset="95%" stopColor="#8b5cf6" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid
                    strokeDasharray="3 3"
                    stroke="rgba(255,255,255,0.04)"
                    vertical={false}
                  />
                  <XAxis
                    dataKey="date"
                    tick={{ fill: "#525252", fontSize: 10, fontWeight: 700 }}
                    axisLine={false}
                    tickLine={false}
                    interval="preserveStartEnd"
                  />
                  <YAxis
                    tick={{ fill: "#525252", fontSize: 10, fontWeight: 700 }}
                    axisLine={false}
                    tickLine={false}
                    tickFormatter={(v: number) => `$${v}`}
                  />
                  <Tooltip
                    {...tooltipStyle}
                    formatter={(v?: ValueType, name?: NameType) => [
                      `$${Number(v ?? 0).toLocaleString()}`,
                      name === "volumeUSDC" ? "USDC" : "XLM",
                    ]}
                  />
                  <Legend
                    wrapperStyle={{
                      fontSize: 11,
                      fontWeight: 800,
                      paddingTop: 12,
                    }}
                    formatter={(value) =>
                      value === "volumeUSDC" ? "USDC Volume" : "XLM Volume"
                    }
                  />
                  <Area
                    type="monotone"
                    dataKey="volumeUSDC"
                    stroke="#6366f1"
                    strokeWidth={2}
                    fill="url(#gUsdc)"
                    dot={false}
                    activeDot={{ r: 5, fill: "#6366f1" }}
                  />
                  <Area
                    type="monotone"
                    dataKey="volumeXLM"
                    stroke="#8b5cf6"
                    strokeWidth={2}
                    fill="url(#gXlm)"
                    dot={false}
                    activeDot={{ r: 5, fill: "#8b5cf6" }}
                  />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* ── Bottom row: Tx Count line + Asset Donut ── */}
        <div className="grid md:grid-cols-2 gap-10">
          {/* Line Chart: Transaction Count */}
          <div>
            <h3 className="text-sm font-black uppercase tracking-widest text-neutral-500 mb-5">
              Transaction Count
            </h3>
            <div className="h-56">
              {loading ? (
                <ChartSkeleton />
              ) : (
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart
                    data={txCount}
                    margin={{ top: 4, right: 4, left: -20, bottom: 0 }}
                  >
                    <CartesianGrid
                      strokeDasharray="3 3"
                      stroke="rgba(255,255,255,0.04)"
                      vertical={false}
                    />
                    <XAxis
                      dataKey="date"
                      tick={{ fill: "#525252", fontSize: 10, fontWeight: 700 }}
                      axisLine={false}
                      tickLine={false}
                      interval="preserveStartEnd"
                    />
                    <YAxis
                      tick={{ fill: "#525252", fontSize: 10, fontWeight: 700 }}
                      axisLine={false}
                      tickLine={false}
                    />
                    <Tooltip
                      {...tooltipStyle}
                      formatter={(v?: ValueType) => [Number(v ?? 0), "Transactions"]}
                    />
                    <Line
                      type="monotone"
                      dataKey="count"
                      stroke="#6366f1"
                      strokeWidth={2.5}
                      dot={false}
                      activeDot={{
                        r: 6,
                        fill: "#6366f1",
                        stroke: "rgba(99,102,241,0.3)",
                        strokeWidth: 6,
                      }}
                    />
                  </LineChart>
                </ResponsiveContainer>
              )}
            </div>
          </div>

          {/* Donut Chart: Asset Distribution */}
          <div>
            <h3 className="text-sm font-black uppercase tracking-widest text-neutral-500 mb-5">
              Asset Distribution
            </h3>
            <div className="h-56 flex items-center justify-center">
              {loading ? (
                <ChartSkeleton />
              ) : (
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={assetDist}
                      cx="50%"
                      cy="50%"
                      innerRadius="52%"
                      outerRadius="75%"
                      dataKey="value"
                      paddingAngle={3}
                      labelLine={false}
                    >
                      {assetDist.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip
                      {...tooltipStyle}
                      formatter={(v?: ValueType, name?: NameType) => [
                        `${Number(v ?? 0)}%`,
                        name ?? "",
                      ]}
                    />
                    <Legend
                      wrapperStyle={{
                        fontSize: 11,
                        fontWeight: 800,
                      }}
                      formatter={(value) => {
                        const found = assetDist.find((d) => d.name === value);
                        return `${value} ${found ? `(${found.value}%)` : ""}`;
                      }}
                    />
                    {/* Centered label rendered manually below via absolute positioning */}
                    <DonutLabel
                      cx={0}
                      cy={0}
                      total={assetDist.reduce((s, d) => s + d.value, 0)}
                    />
                  </PieChart>
                </ResponsiveContainer>
              )}
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
