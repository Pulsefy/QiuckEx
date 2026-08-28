"use client";

/**
 * PaymentHistoryFilters
 *
 * Full-featured filter/search panel for the payment history table.
 * Implements #64 acceptance criteria:
 *  - Filter by date, asset, amount, memo
 *  - Search by tx hash, memo, counterparty
 *  - Export CSV / PDF
 *  - Saved filter presets
 *  - URL query params reflect active filters
 *  - Empty state handled by parent via `hasResults` prop
 */

import { useCallback, useEffect, useRef, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import {
  type ActivityFilterState,
  type ActivityFeedItem,
  type FilterPreset,
  DEFAULT_FILTERS,
  downloadCsv,
  filtersToParams,
  loadPresets,
  paramsToFilters,
  printToPdf,
  savePreset,
  deletePreset,
  hasActiveFilters,
} from "@/lib/activityFilters";
import type { ActivityFeedItem as AFI } from "@/hooks/activityFeedApi";

interface PaymentHistoryFiltersProps {
  /** All unfiltered items (for computing asset options and export) */
  allItems: AFI[];
  /** Currently filtered items (for export and counts) */
  filteredItems: AFI[];
  filters: ActivityFilterState;
  onFiltersChange: (f: ActivityFilterState) => void;
  assetOptions: string[];
}

const INPUT_CLASS =
  "bg-card border border-border-strong rounded-xl px-3 py-2 text-sm outline-none focus:border-indigo-500 transition w-full";
const LABEL_CLASS = "block text-xs text-subtle font-semibold mb-1 uppercase tracking-wide";

export function PaymentHistoryFilters({
  allItems,
  filteredItems,
  filters,
  onFiltersChange,
  assetOptions,
}: PaymentHistoryFiltersProps) {
  const router       = useRouter();
  const searchParams = useSearchParams();
  const initialized  = useRef(false);

  const [presets, setPresets]             = useState<FilterPreset[]>([]);
  const [showAdvanced, setShowAdvanced]   = useState(false);
  const [presetName, setPresetName]       = useState("");
  const [showPresetInput, setShowPresetInput] = useState(false);

  // -------------------------------------------------------------------------
  // Initialise from URL on mount
  // -------------------------------------------------------------------------
  useEffect(() => {
    if (initialized.current) return;
    initialized.current = true;
    const fromUrl = paramsToFilters(searchParams);
    if (hasActiveFilters(fromUrl)) {
      onFiltersChange(fromUrl);
      if (fromUrl.dateFrom || fromUrl.dateTo || fromUrl.amountMin || fromUrl.amountMax || fromUrl.memo) {
        setShowAdvanced(true);
      }
    }
    setPresets(loadPresets());
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // -------------------------------------------------------------------------
  // Sync active filters into URL
  // -------------------------------------------------------------------------
  useEffect(() => {
    if (!initialized.current) return;
    const params = filtersToParams(filters);
    const qs     = params.toString();
    const target = qs ? `?${qs}` : window.location.pathname;
    router.replace(target, { scroll: false });
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filters]);

  // -------------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------------
  const update = useCallback(
    (patch: Partial<ActivityFilterState>) => {
      onFiltersChange({ ...filters, ...patch });
    },
    [filters, onFiltersChange],
  );

  const clearAll = () => {
    onFiltersChange({ ...DEFAULT_FILTERS });
    setShowAdvanced(false);
  };

  const handleSavePreset = () => {
    if (!presetName.trim()) return;
    const preset: FilterPreset = {
      id:      Date.now().toString(),
      name:    presetName.trim(),
      filters: { ...filters },
    };
    savePreset(preset);
    setPresets(loadPresets());
    setPresetName("");
    setShowPresetInput(false);
  };

  const handleDeletePreset = (id: string) => {
    deletePreset(id);
    setPresets(loadPresets());
  };

  const applyPreset = (preset: FilterPreset) => {
    onFiltersChange({ ...preset.filters });
    if (
      preset.filters.dateFrom ||
      preset.filters.dateTo ||
      preset.filters.amountMin ||
      preset.filters.amountMax ||
      preset.filters.memo
    ) {
      setShowAdvanced(true);
    }
  };

  const active = hasActiveFilters(filters);

  // -------------------------------------------------------------------------
  // Render
  // -------------------------------------------------------------------------
  return (
    <div className="space-y-3">
      {/* --- Row 1: search + basic filters --- */}
      <div className="flex flex-wrap gap-3 items-end">
        {/* Full-text search */}
        <div className="flex-1 min-w-[200px]">
          <label className={LABEL_CLASS}>Search</label>
          <div className="relative">
            <span className="absolute left-3 top-1/2 -translate-y-1/2 text-subtle text-sm">🔍</span>
            <input
              type="text"
              value={filters.query}
              onChange={(e) => update({ query: e.target.value })}
              placeholder="TX hash, memo, address…"
              className={`${INPUT_CLASS} pl-8`}
            />
          </div>
        </div>

        {/* Status */}
        <div className="min-w-[130px]">
          <label className={LABEL_CLASS}>Status</label>
          <select
            value={filters.status}
            onChange={(e) => update({ status: e.target.value as ActivityFilterState["status"] })}
            className={INPUT_CLASS}
          >
            <option value="All">All statuses</option>
            <option value="Settled">Settled</option>
            <option value="Pending">Pending</option>
          </select>
        </div>

        {/* Asset */}
        <div className="min-w-[130px]">
          <label className={LABEL_CLASS}>Asset</label>
          <select
            value={filters.asset}
            onChange={(e) => update({ asset: e.target.value })}
            className={INPUT_CLASS}
          >
            {assetOptions.map((a) => (
              <option key={a} value={a}>
                {a === "All" ? "All assets" : a}
              </option>
            ))}
          </select>
        </div>

        {/* Toggle advanced */}
        <button
          type="button"
          onClick={() => setShowAdvanced((v) => !v)}
          className={`px-3 py-2 rounded-xl border text-sm font-semibold transition ${
            showAdvanced
              ? "border-indigo-500/40 bg-indigo-500/10 text-indigo-400"
              : "border-border-strong text-subtle hover:text-foreground hover:bg-surface"
          }`}
        >
          {showAdvanced ? "▲ Less" : "▼ More filters"}
        </button>

        {/* Clear */}
        {active && (
          <button
            type="button"
            onClick={clearAll}
            className="px-3 py-2 rounded-xl border border-border-strong text-sm font-semibold text-subtle hover:text-red-400 transition"
          >
            ✕ Clear
          </button>
        )}
      </div>

      {/* --- Row 2: advanced filters --- */}
      {showAdvanced && (
        <div className="flex flex-wrap gap-3 items-end p-4 rounded-2xl bg-surface border border-border">
          {/* Date from */}
          <div className="min-w-[160px]">
            <label className={LABEL_CLASS}>From date</label>
            <input
              type="date"
              value={filters.dateFrom ?? ""}
              onChange={(e) => update({ dateFrom: e.target.value || undefined })}
              className={INPUT_CLASS}
            />
          </div>

          {/* Date to */}
          <div className="min-w-[160px]">
            <label className={LABEL_CLASS}>To date</label>
            <input
              type="date"
              value={filters.dateTo ?? ""}
              onChange={(e) => update({ dateTo: e.target.value || undefined })}
              className={INPUT_CLASS}
            />
          </div>

          {/* Amount min */}
          <div className="min-w-[120px]">
            <label className={LABEL_CLASS}>Min amount</label>
            <input
              type="number"
              min="0"
              step="any"
              value={filters.amountMin ?? ""}
              onChange={(e) => update({ amountMin: e.target.value || undefined })}
              placeholder="0"
              className={INPUT_CLASS}
            />
          </div>

          {/* Amount max */}
          <div className="min-w-[120px]">
            <label className={LABEL_CLASS}>Max amount</label>
            <input
              type="number"
              min="0"
              step="any"
              value={filters.amountMax ?? ""}
              onChange={(e) => update({ amountMax: e.target.value || undefined })}
              placeholder="∞"
              className={INPUT_CLASS}
            />
          </div>

          {/* Memo search */}
          <div className="flex-1 min-w-[160px]">
            <label className={LABEL_CLASS}>Memo contains</label>
            <input
              type="text"
              value={filters.memo ?? ""}
              onChange={(e) => update({ memo: e.target.value || undefined })}
              placeholder="Invoice #, note…"
              className={INPUT_CLASS}
            />
          </div>
        </div>
      )}

      {/* --- Row 3: presets + export --- */}
      <div className="flex flex-wrap gap-3 items-center justify-between">
        {/* Left: saved presets */}
        <div className="flex flex-wrap gap-2 items-center">
          {presets.map((preset) => (
            <div key={preset.id} className="flex items-center gap-1">
              <button
                type="button"
                onClick={() => applyPreset(preset)}
                className="px-3 py-1.5 text-xs font-semibold rounded-lg bg-surface border border-border hover:border-indigo-500/40 hover:text-indigo-400 transition"
              >
                📌 {preset.name}
              </button>
              <button
                type="button"
                onClick={() => handleDeletePreset(preset.id)}
                className="text-subtle hover:text-red-400 transition text-xs px-1"
                title="Delete preset"
              >
                ✕
              </button>
            </div>
          ))}

          {/* Save current as preset */}
          {active && !showPresetInput && (
            <button
              type="button"
              onClick={() => setShowPresetInput(true)}
              className="px-3 py-1.5 text-xs font-semibold rounded-lg border border-dashed border-border text-subtle hover:border-indigo-500/40 hover:text-indigo-400 transition"
            >
              + Save preset
            </button>
          )}
          {showPresetInput && (
            <div className="flex gap-2 items-center">
              <input
                type="text"
                value={presetName}
                onChange={(e) => setPresetName(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleSavePreset()}
                placeholder="Preset name"
                className="bg-card border border-border-strong rounded-lg px-3 py-1.5 text-xs outline-none focus:border-indigo-500 transition w-40"
                autoFocus
              />
              <button
                type="button"
                onClick={handleSavePreset}
                disabled={!presetName.trim()}
                className="px-3 py-1.5 text-xs font-semibold bg-indigo-500 text-white rounded-lg hover:bg-indigo-400 disabled:opacity-50 transition"
              >
                Save
              </button>
              <button
                type="button"
                onClick={() => { setShowPresetInput(false); setPresetName(""); }}
                className="text-subtle hover:text-foreground text-xs"
              >
                Cancel
              </button>
            </div>
          )}
        </div>

        {/* Right: export buttons */}
        <div className="flex gap-2">
          <button
            type="button"
            onClick={() => downloadCsv(filteredItems)}
            disabled={filteredItems.length === 0}
            className="px-3 py-1.5 text-xs font-semibold rounded-lg border border-border-strong text-subtle hover:text-foreground hover:bg-surface disabled:opacity-40 transition flex items-center gap-1.5"
          >
            ⬇ CSV
          </button>
          <button
            type="button"
            onClick={() => printToPdf(filteredItems)}
            disabled={filteredItems.length === 0}
            className="px-3 py-1.5 text-xs font-semibold rounded-lg border border-border-strong text-subtle hover:text-foreground hover:bg-surface disabled:opacity-40 transition flex items-center gap-1.5"
          >
            🖨 PDF
          </button>
        </div>
      </div>

      {/* Active filter summary */}
      {active && (
        <p className="text-xs text-subtle">
          Showing{" "}
          <span className="font-semibold text-foreground">
            {filteredItems.length}
          </span>{" "}
          of{" "}
          <span className="font-semibold text-foreground">
            {allItems.length}
          </span>{" "}
          transactions
        </p>
      )}
    </div>
  );
}
