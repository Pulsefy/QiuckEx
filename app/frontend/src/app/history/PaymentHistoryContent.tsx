"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import Link from "next/link";
import { fetchActivityFeed, type ActivityFeedItem } from "@/hooks/activityFeedApi";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type StatusFilter = "All" | "Settled" | "Pending";
type DateRange = "All" | "24h" | "7d" | "30d" | "custom";
type SortField = "date" | "amount";
type SortDir = "desc" | "asc";

interface FilterState {
  query: string;
  status: StatusFilter;
  asset: string;
  dateRange: DateRange;
  dateFrom: string;
  dateTo: string;
  amountMin: string;
  amountMax: string;
}

interface SavedPreset {
  id: string;
  name: string;
  filters: FilterState;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const EMPTY_FILTERS: FilterState = {
  query: "",
  status: "All",
  asset: "All",
  dateRange: "All",
  dateFrom: "",
  dateTo: "",
  amountMin: "",
  amountMax: "",
};

const STELLAR_EXPLORER = "https://stellar.expert/explorer/public/tx/";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatDate(iso: string): string {
  try {
    return new Date(iso).toLocaleDateString("en-US", {
      month: "short",
      day: "numeric",
      year: "numeric",
    });
  } catch {
    return iso;
  }
}

function formatAmount(amount: string): string {
  const n = parseFloat(amount);
  return isNaN(n) ? amount : n.toLocaleString("en-US", { maximumFractionDigits: 7 });
}

function shortAddress(addr: string): string {
  if (!addr || addr.length < 12) return addr;
  return `${addr.slice(0, 6)}…${addr.slice(-4)}`;
}

function isWithinDateRange(timestamp: string, range: DateRange, from: string, to: string): boolean {
  if (range === "All") return true;
  const ts = new Date(timestamp).getTime();
  const now = Date.now();
  if (range === "24h") return now - ts <= 24 * 3600 * 1000;
  if (range === "7d") return now - ts <= 7 * 24 * 3600 * 1000;
  if (range === "30d") return now - ts <= 30 * 24 * 3600 * 1000;
  if (range === "custom") {
    const fromMs = from ? new Date(from).getTime() : 0;
    const toMs = to ? new Date(to).getTime() + 86400000 : Infinity;
    return ts >= fromMs && ts <= toMs;
  }
  return true;
}

function applyFilters(
  items: ActivityFeedItem[],
  filters: FilterState,
): ActivityFeedItem[] {
  const q = filters.query.trim().toLowerCase();
  return items.filter((item) => {
    if (filters.status !== "All" && item.status !== filters.status) return false;
    if (
      filters.asset !== "All" &&
      filters.asset !== "" &&
      item.asset.toLowerCase() !== filters.asset.toLowerCase()
    )
      return false;
    if (!isWithinDateRange(item.timestamp, filters.dateRange, filters.dateFrom, filters.dateTo))
      return false;

    const amt = parseFloat(item.amount);
    if (filters.amountMin !== "" && !isNaN(parseFloat(filters.amountMin))) {
      if (amt < parseFloat(filters.amountMin)) return false;
    }
    if (filters.amountMax !== "" && !isNaN(parseFloat(filters.amountMax))) {
      if (amt > parseFloat(filters.amountMax)) return false;
    }

    if (!q) return true;
    const searchable = [
      item.id,
      item.amount,
      item.asset,
      item.memo ?? "",
      item.source,
      item.destination,
    ]
      .join(" ")
      .toLowerCase();
    return searchable.includes(q);
  });
}

function filtersToSearchParams(filters: FilterState): URLSearchParams {
  const params = new URLSearchParams();
  if (filters.query) params.set("q", filters.query);
  if (filters.status !== "All") params.set("status", filters.status);
  if (filters.asset !== "All" && filters.asset) params.set("asset", filters.asset);
  if (filters.dateRange !== "All") params.set("range", filters.dateRange);
  if (filters.dateFrom) params.set("from", filters.dateFrom);
  if (filters.dateTo) params.set("to", filters.dateTo);
  if (filters.amountMin) params.set("amtMin", filters.amountMin);
  if (filters.amountMax) params.set("amtMax", filters.amountMax);
  return params;
}

function filtersFromSearchParams(params: URLSearchParams): FilterState {
  const range = (params.get("range") ?? "All") as DateRange;
  return {
    query: params.get("q") ?? "",
    status: (params.get("status") as StatusFilter) ?? "All",
    asset: params.get("asset") ?? "All",
    dateRange: range,
    dateFrom: params.get("from") ?? "",
    dateTo: params.get("to") ?? "",
    amountMin: params.get("amtMin") ?? "",
    amountMax: params.get("amtMax") ?? "",
  };
}

function exportCsv(items: ActivityFeedItem[]): void {
  const header = ["Date", "Status", "Amount", "Asset", "Memo", "From", "To", "TxHash"];
  const rows = items.map((it) => [
    new Date(it.timestamp).toISOString(),
    it.status,
    it.amount,
    it.asset,
    it.memo ?? "",
    it.source,
    it.destination,
    it.id,
  ]);
  const csv = [header, ...rows]
    .map((r) => r.map((c) => `"${String(c).replace(/"/g, '""')}"`).join(","))
    .join("\n");

  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `quickex-transactions-${Date.now()}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

function exportPdf(items: ActivityFeedItem[]): void {
  // Build minimal HTML and open as print dialog
  const rows = items
    .map(
      (it) =>
        `<tr>
          <td>${new Date(it.timestamp).toLocaleDateString()}</td>
          <td>${it.status}</td>
          <td>${it.amount} ${it.asset}</td>
          <td>${it.memo ?? "—"}</td>
          <td>${shortAddress(it.source)}</td>
          <td>${shortAddress(it.destination)}</td>
        </tr>`,
    )
    .join("");

  const html = `<!DOCTYPE html>
<html>
<head>
  <title>QuickEx Transaction History</title>
  <style>
    body { font-family: sans-serif; font-size: 12px; }
    table { width: 100%; border-collapse: collapse; }
    th, td { border: 1px solid #ccc; padding: 6px 8px; text-align: left; }
    th { background: #f0f0f0; }
  </style>
</head>
<body>
  <h2>QuickEx Transaction History</h2>
  <p>Exported on ${new Date().toLocaleString()}</p>
  <table>
    <thead>
      <tr><th>Date</th><th>Status</th><th>Amount</th><th>Memo</th><th>From</th><th>To</th></tr>
    </thead>
    <tbody>${rows}</tbody>
  </table>
</body>
</html>`;

  const win = window.open("", "_blank");
  if (win) {
    win.document.write(html);
    win.document.close();
    win.print();
  }
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function PaymentHistoryContent() {
  const searchParams = useSearchParams();
  const router = useRouter();

  const [items, setItems] = useState<ActivityFeedItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [degraded, setDegraded] = useState(false);

  const [filters, setFilters] = useState<FilterState>(() =>
    filtersFromSearchParams(searchParams),
  );

  const [sortField, setSortField] = useState<SortField>("date");
  const [sortDir, setSortDir] = useState<SortDir>("desc");

  const [savedPresets, setSavedPresets] = useState<SavedPreset[]>(() => {
    try {
      const raw =
        typeof window !== "undefined"
          ? window.localStorage.getItem("quickex.filterPresets")
          : null;
      return raw ? (JSON.parse(raw) as SavedPreset[]) : [];
    } catch {
      return [];
    }
  });
  const [presetName, setPresetName] = useState("");
  const [showPresetSave, setShowPresetSave] = useState(false);
  const [presetSaved, setPresetSaved] = useState(false);

  const [showFilters, setShowFilters] = useState(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Available assets derived from loaded data
  const availableAssets = useMemo(
    () => Array.from(new Set(items.map((i) => i.asset))).sort(),
    [items],
  );

  // ---------------------------------------------------------------------------
  // Load data
  // ---------------------------------------------------------------------------

  useEffect(() => {
    setLoading(true);
    fetchActivityFeed(200).then(({ items: fetched, degraded: deg }) => {
      setItems(fetched);
      setDegraded(deg);
      setLoading(false);
    });
  }, []);

  // ---------------------------------------------------------------------------
  // Sync filters → URL (debounced)
  // ---------------------------------------------------------------------------

  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => {
      const params = filtersToSearchParams(filters);
      const qs = params.toString();
      router.replace(qs ? `/history?${qs}` : "/history", { scroll: false });
    }, 300);
    return () => {
      if (debounceRef.current) clearTimeout(debounceRef.current);
    };
  }, [filters, router]);

  // ---------------------------------------------------------------------------
  // Filtered + sorted items
  // ---------------------------------------------------------------------------

  const filtered = useMemo(() => {
    const result = applyFilters(items, filters);
    return result.sort((a, b) => {
      if (sortField === "date") {
        const diff = new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime();
        return sortDir === "desc" ? diff : -diff;
      }
      if (sortField === "amount") {
        const diff = parseFloat(b.amount) - parseFloat(a.amount);
        return sortDir === "desc" ? diff : -diff;
      }
      return 0;
    });
  }, [items, filters, sortField, sortDir]);

  // ---------------------------------------------------------------------------
  // Actions
  // ---------------------------------------------------------------------------

  const updateFilter = <K extends keyof FilterState>(key: K, val: FilterState[K]) => {
    setFilters((prev) => ({ ...prev, [key]: val }));
  };

  const clearFilters = () => setFilters(EMPTY_FILTERS);

  const hasActiveFilters = Object.entries(filters).some(([k, v]) => {
    if (k === "status" || k === "asset" || k === "dateRange") return v !== "All" && v !== "";
    return v !== "" && v !== "All";
  });

  const toggleSort = (field: SortField) => {
    if (sortField === field) {
      setSortDir((d) => (d === "desc" ? "asc" : "desc"));
    } else {
      setSortField(field);
      setSortDir("desc");
    }
  };

  const handleCopy = async (text: string, id: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedId(id);
      setTimeout(() => setCopiedId(null), 1800);
    } catch {/* */ }
  };

  const savePreset = () => {
    if (!presetName.trim()) return;
    const preset: SavedPreset = {
      id: Date.now().toString(),
      name: presetName.trim(),
      filters: { ...filters },
    };
    const updated = [...savedPresets, preset];
    setSavedPresets(updated);
    try {
      window.localStorage.setItem("quickex.filterPresets", JSON.stringify(updated));
    } catch {/* */ }
    setPresetName("");
    setShowPresetSave(false);
    setPresetSaved(true);
    setTimeout(() => setPresetSaved(false), 2000);
  };

  const loadPreset = (preset: SavedPreset) => {
    setFilters(preset.filters);
  };

  const deletePreset = (id: string) => {
    const updated = savedPresets.filter((p) => p.id !== id);
    setSavedPresets(updated);
    try {
      window.localStorage.setItem("quickex.filterPresets", JSON.stringify(updated));
    } catch {/* */ }
  };

  // ---------------------------------------------------------------------------
  // Empty state suggestions
  // ---------------------------------------------------------------------------

  const EmptyState = () => (
    <div className="flex flex-col items-center justify-center py-20 text-center">
      <div className="text-5xl mb-4">🔍</div>
      <h3 className="text-lg font-bold mb-2">No transactions found</h3>
      <p className="text-subtle text-sm max-w-sm mb-6">
        {hasActiveFilters
          ? "Try adjusting your filters — you may be filtering too strictly."
          : "No transactions yet. Once you send or receive payments they will appear here."}
      </p>
      {hasActiveFilters && (
        <div className="flex flex-wrap gap-3 justify-center">
          <button
            onClick={clearFilters}
            className="px-4 py-2 bg-indigo-500 text-white text-sm font-bold rounded-xl hover:bg-indigo-400 transition"
          >
            Clear all filters
          </button>
          <button
            onClick={() => updateFilter("dateRange", "All")}
            className="px-4 py-2 border border-border-strong text-sm font-semibold rounded-xl hover:bg-surface transition"
          >
            Show all dates
          </button>
          <button
            onClick={() => updateFilter("status", "All")}
            className="px-4 py-2 border border-border-strong text-sm font-semibold rounded-xl hover:bg-surface transition"
          >
            Show all statuses
          </button>
        </div>
      )}
    </div>
  );

  // ---------------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------------

  return (
    <div className="relative min-h-screen text-foreground">
      {/* Background glow */}
      <div className="fixed top-[-20%] right-[-20%] w-[50%] h-[50%] bg-indigo-500/8 blur-[120px] rounded-full pointer-events-none" />

      <main className="relative z-10 max-w-7xl mx-auto p-4 sm:p-6 lg:p-10">
        {/* Header */}
        <header className="mb-8 flex flex-wrap items-start justify-between gap-4">
          <div>
            <div className="flex items-center gap-3 mb-1">
              <Link
                href="/dashboard"
                className="text-subtle hover:text-foreground text-sm font-semibold transition"
              >
                ← Dashboard
              </Link>
            </div>
            <h1 className="text-3xl font-black tracking-tight">
              Payment History
            </h1>
            <p className="text-subtle text-sm mt-1">
              {filtered.length} transaction{filtered.length !== 1 ? "s" : ""}
              {hasActiveFilters ? " (filtered)" : ""}
              {degraded && (
                <span className="ml-2 text-amber-400 text-xs font-bold">
                  ⚠ Showing cached data
                </span>
              )}
            </p>
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            <button
              onClick={() => exportCsv(filtered)}
              disabled={filtered.length === 0}
              className="px-4 py-2 border border-border-strong text-sm font-bold rounded-xl hover:bg-surface transition disabled:opacity-40"
              title="Export as CSV"
            >
              ↓ CSV
            </button>
            <button
              onClick={() => exportPdf(filtered)}
              disabled={filtered.length === 0}
              className="px-4 py-2 border border-border-strong text-sm font-bold rounded-xl hover:bg-surface transition disabled:opacity-40"
              title="Export as PDF"
            >
              ↓ PDF
            </button>
            <button
              onClick={() => setShowFilters((s) => !s)}
              className={`px-4 py-2 text-sm font-bold rounded-xl border transition ${
                showFilters || hasActiveFilters
                  ? "bg-indigo-500/20 border-indigo-500/50 text-indigo-300"
                  : "border-border-strong hover:bg-surface"
              }`}
            >
              ⚙ Filters{hasActiveFilters ? " •" : ""}
            </button>
          </div>
        </header>

        {/* Search bar (always visible) */}
        <div className="mb-4 relative">
          <span className="absolute left-4 top-1/2 -translate-y-1/2 text-subtle text-sm pointer-events-none">
            🔍
          </span>
          <input
            type="text"
            value={filters.query}
            onChange={(e) => updateFilter("query", e.target.value)}
            placeholder="Search by tx hash, memo, address…"
            className="w-full pl-10 pr-4 py-3 bg-card border border-border rounded-2xl text-sm outline-none focus:border-indigo-500 transition"
            aria-label="Search transactions"
          />
          {filters.query && (
            <button
              onClick={() => updateFilter("query", "")}
              className="absolute right-4 top-1/2 -translate-y-1/2 text-subtle hover:text-foreground transition text-sm"
              aria-label="Clear search"
            >
              ✕
            </button>
          )}
        </div>

        {/* Expanded filter panel */}
        {showFilters && (
          <div className="mb-6 p-6 rounded-3xl bg-card border border-border space-y-5">
            <div className="flex items-center justify-between flex-wrap gap-2">
              <h3 className="font-bold">Filters</h3>
              {hasActiveFilters && (
                <button
                  onClick={clearFilters}
                  className="text-xs text-indigo-400 hover:text-indigo-300 font-bold transition"
                >
                  Clear all
                </button>
              )}
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-4">
              {/* Status */}
              <div>
                <label className="block text-xs font-bold text-subtle mb-1 uppercase tracking-wider">
                  Status
                </label>
                <select
                  value={filters.status}
                  onChange={(e) => updateFilter("status", e.target.value as StatusFilter)}
                  className="w-full bg-surface border border-border-strong rounded-xl px-3 py-2 text-sm outline-none focus:border-indigo-500 transition"
                >
                  <option value="All">All</option>
                  <option value="Settled">Settled</option>
                  <option value="Pending">Pending</option>
                </select>
              </div>

              {/* Asset */}
              <div>
                <label className="block text-xs font-bold text-subtle mb-1 uppercase tracking-wider">
                  Asset
                </label>
                <select
                  value={filters.asset}
                  onChange={(e) => updateFilter("asset", e.target.value)}
                  className="w-full bg-surface border border-border-strong rounded-xl px-3 py-2 text-sm outline-none focus:border-indigo-500 transition"
                >
                  <option value="All">All assets</option>
                  {availableAssets.map((a) => (
                    <option key={a} value={a}>
                      {a}
                    </option>
                  ))}
                </select>
              </div>

              {/* Date range */}
              <div>
                <label className="block text-xs font-bold text-subtle mb-1 uppercase tracking-wider">
                  Date Range
                </label>
                <select
                  value={filters.dateRange}
                  onChange={(e) => updateFilter("dateRange", e.target.value as DateRange)}
                  className="w-full bg-surface border border-border-strong rounded-xl px-3 py-2 text-sm outline-none focus:border-indigo-500 transition"
                >
                  <option value="All">All time</option>
                  <option value="24h">Last 24h</option>
                  <option value="7d">Last 7 days</option>
                  <option value="30d">Last 30 days</option>
                  <option value="custom">Custom range</option>
                </select>
              </div>

              {/* Amount min/max */}
              <div>
                <label className="block text-xs font-bold text-subtle mb-1 uppercase tracking-wider">
                  Amount (min)
                </label>
                <input
                  type="number"
                  min="0"
                  value={filters.amountMin}
                  onChange={(e) => updateFilter("amountMin", e.target.value)}
                  placeholder="0"
                  className="w-full bg-surface border border-border-strong rounded-xl px-3 py-2 text-sm outline-none focus:border-indigo-500 transition"
                />
              </div>

              <div>
                <label className="block text-xs font-bold text-subtle mb-1 uppercase tracking-wider">
                  Amount (max)
                </label>
                <input
                  type="number"
                  min="0"
                  value={filters.amountMax}
                  onChange={(e) => updateFilter("amountMax", e.target.value)}
                  placeholder="No limit"
                  className="w-full bg-surface border border-border-strong rounded-xl px-3 py-2 text-sm outline-none focus:border-indigo-500 transition"
                />
              </div>
            </div>

            {/* Custom date range pickers */}
            {filters.dateRange === "custom" && (
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-bold text-subtle mb-1 uppercase tracking-wider">
                    From
                  </label>
                  <input
                    type="date"
                    value={filters.dateFrom}
                    onChange={(e) => updateFilter("dateFrom", e.target.value)}
                    className="w-full bg-surface border border-border-strong rounded-xl px-3 py-2 text-sm outline-none focus:border-indigo-500 transition"
                  />
                </div>
                <div>
                  <label className="block text-xs font-bold text-subtle mb-1 uppercase tracking-wider">
                    To
                  </label>
                  <input
                    type="date"
                    value={filters.dateTo}
                    onChange={(e) => updateFilter("dateTo", e.target.value)}
                    className="w-full bg-surface border border-border-strong rounded-xl px-3 py-2 text-sm outline-none focus:border-indigo-500 transition"
                  />
                </div>
              </div>
            )}

            {/* Saved presets */}
            <div className="border-t border-border pt-4">
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs font-bold text-subtle uppercase tracking-wider">
                  Saved Presets
                </span>
                <button
                  onClick={() => setShowPresetSave((s) => !s)}
                  className="text-xs text-indigo-400 hover:text-indigo-300 font-bold transition"
                >
                  + Save current
                </button>
              </div>

              {showPresetSave && (
                <div className="flex gap-2 mb-3">
                  <input
                    type="text"
                    value={presetName}
                    onChange={(e) => setPresetName(e.target.value)}
                    placeholder="Preset name"
                    maxLength={32}
                    className="flex-1 bg-surface border border-border-strong rounded-xl px-3 py-2 text-sm outline-none focus:border-indigo-500 transition"
                    onKeyDown={(e) => e.key === "Enter" && savePreset()}
                  />
                  <button
                    onClick={savePreset}
                    disabled={!presetName.trim()}
                    className="px-4 py-2 bg-indigo-500 text-white text-sm font-bold rounded-xl hover:bg-indigo-400 transition disabled:opacity-50"
                  >
                    Save
                  </button>
                </div>
              )}

              {presetSaved && (
                <p className="text-xs text-emerald-400 mb-2">✓ Preset saved</p>
              )}

              {savedPresets.length === 0 ? (
                <p className="text-xs text-subtle">No presets saved yet.</p>
              ) : (
                <div className="flex flex-wrap gap-2">
                  {savedPresets.map((p) => (
                    <div
                      key={p.id}
                      className="flex items-center gap-1.5 px-3 py-1.5 bg-surface border border-border-strong rounded-xl text-xs"
                    >
                      <button
                        onClick={() => loadPreset(p)}
                        className="font-semibold hover:text-indigo-400 transition"
                      >
                        {p.name}
                      </button>
                      <button
                        onClick={() => deletePreset(p.id)}
                        className="text-subtle hover:text-red-400 transition"
                        aria-label={`Delete preset ${p.name}`}
                      >
                        ✕
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {/* Quick filter chips */}
        <div className="flex flex-wrap gap-2 mb-6">
          {(["All", "Settled", "Pending"] as StatusFilter[]).map((s) => (
            <button
              key={s}
              onClick={() => updateFilter("status", s)}
              className={`px-3 py-1.5 rounded-xl text-xs font-bold border transition ${
                filters.status === s
                  ? "bg-indigo-500/20 border-indigo-500/50 text-indigo-300"
                  : "border-border-strong text-subtle hover:text-foreground hover:bg-surface"
              }`}
            >
              {s}
            </button>
          ))}
          <span className="w-px bg-border self-stretch mx-1" />
          {(["All", "24h", "7d", "30d"] as DateRange[]).map((r) => (
            <button
              key={r}
              onClick={() => updateFilter("dateRange", r as DateRange)}
              className={`px-3 py-1.5 rounded-xl text-xs font-bold border transition ${
                filters.dateRange === r
                  ? "bg-indigo-500/20 border-indigo-500/50 text-indigo-300"
                  : "border-border-strong text-subtle hover:text-foreground hover:bg-surface"
              }`}
            >
              {r === "All" ? "All time" : r}
            </button>
          ))}
        </div>

        {/* Loading */}
        {loading && (
          <div className="py-20 text-center">
            <div className="w-8 h-8 border-2 border-indigo-500 border-t-transparent rounded-full animate-spin mx-auto mb-4" />
            <p className="text-subtle text-sm">Loading transactions…</p>
          </div>
        )}

        {/* Transaction table */}
        {!loading && filtered.length > 0 && (
          <div className="rounded-3xl bg-card border border-border overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left">
                <thead>
                  <tr className="border-b border-border text-subtle text-xs font-bold uppercase tracking-wider">
                    <th className="px-6 py-4">
                      <button
                        onClick={() => toggleSort("date")}
                        className="flex items-center gap-1 hover:text-foreground transition"
                      >
                        Date
                        {sortField === "date" && (
                          <span>{sortDir === "desc" ? "↓" : "↑"}</span>
                        )}
                      </button>
                    </th>
                    <th className="px-6 py-4">Status</th>
                    <th className="px-6 py-4">
                      <button
                        onClick={() => toggleSort("amount")}
                        className="flex items-center gap-1 hover:text-foreground transition"
                      >
                        Amount
                        {sortField === "amount" && (
                          <span>{sortDir === "desc" ? "↓" : "↑"}</span>
                        )}
                      </button>
                    </th>
                    <th className="px-6 py-4">Memo</th>
                    <th className="px-6 py-4">From</th>
                    <th className="px-6 py-4">To</th>
                    <th className="px-6 py-4 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {filtered.map((item) => (
                    <tr
                      key={item.id}
                      className="hover:bg-white/[0.015] transition group"
                    >
                      <td className="px-6 py-4 text-sm text-subtle whitespace-nowrap">
                        {formatDate(item.timestamp)}
                      </td>
                      <td className="px-6 py-4">
                        <span
                          className={`px-2 py-1 rounded-md text-[10px] font-black uppercase tracking-widest ${
                            item.status === "Settled"
                              ? "bg-emerald-500/10 text-emerald-400"
                              : "bg-amber-500/10 text-amber-400"
                          }`}
                        >
                          {item.status}
                        </span>
                      </td>
                      <td className="px-6 py-4">
                        <span className="font-bold">{formatAmount(item.amount)}</span>
                        <span className="ml-1 text-xs text-indigo-400 font-semibold">
                          {item.asset}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-sm text-subtle max-w-[160px] truncate">
                        {item.memo ?? <span className="opacity-40">—</span>}
                      </td>
                      <td className="px-6 py-4">
                        <button
                          onClick={() => handleCopy(item.source, `src-${item.id}`)}
                          className="text-xs font-mono text-subtle hover:text-foreground transition"
                          title={item.source}
                        >
                          {copiedId === `src-${item.id}` ? (
                            <span className="text-emerald-400">✓ Copied</span>
                          ) : (
                            shortAddress(item.source)
                          )}
                        </button>
                      </td>
                      <td className="px-6 py-4">
                        <button
                          onClick={() => handleCopy(item.destination, `dst-${item.id}`)}
                          className="text-xs font-mono text-subtle hover:text-foreground transition"
                          title={item.destination}
                        >
                          {copiedId === `dst-${item.id}` ? (
                            <span className="text-emerald-400">✓ Copied</span>
                          ) : (
                            shortAddress(item.destination)
                          )}
                        </button>
                      </td>
                      <td className="px-6 py-4 text-right">
                        <div className="flex items-center justify-end gap-2 opacity-0 group-hover:opacity-100 transition">
                          <button
                            onClick={() => handleCopy(item.id, `hash-${item.id}`)}
                            className="p-1.5 rounded-lg hover:bg-surface text-subtle hover:text-foreground transition text-xs"
                            title="Copy tx hash"
                            aria-label="Copy transaction hash"
                          >
                            {copiedId === `hash-${item.id}` ? "✓" : "⧉"}
                          </button>
                          <a
                            href={`${STELLAR_EXPLORER}${item.id}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="p-1.5 rounded-lg hover:bg-surface text-subtle hover:text-indigo-400 transition text-xs"
                            title="Open in Stellar Explorer"
                            aria-label="Open in Stellar Explorer"
                          >
                            ↗
                          </a>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Empty state */}
        {!loading && filtered.length === 0 && <EmptyState />}
      </main>
    </div>
  );
}
