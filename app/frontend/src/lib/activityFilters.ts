import type { ActivityFeedItem } from '@/hooks/activityFeedApi';

export type ActivityFilterStatus = 'All' | ActivityFeedItem['status'];

/**
 * Extended filter state for payment history.
 *
 * New in #64:
 *  - dateFrom / dateTo   → ISO date strings (YYYY-MM-DD)
 *  - amountMin / amountMax → decimal strings
 *  - memo                 → free-text match against memo field only
 *  - presetName           → label for a saved preset (UI hint only)
 */
export type ActivityFilterState = {
  query: string;
  status: ActivityFilterStatus;
  asset: string;
  /** ISO date string YYYY-MM-DD – inclusive lower bound */
  dateFrom?: string;
  /** ISO date string YYYY-MM-DD – inclusive upper bound */
  dateTo?: string;
  /** Minimum transaction amount (numeric string) */
  amountMin?: string;
  /** Maximum transaction amount (numeric string) */
  amountMax?: string;
  /** Searches only the memo field */
  memo?: string;
};

export const DEFAULT_FILTERS: ActivityFilterState = {
  query: '',
  status: 'All',
  asset: 'All',
};

// ---------------------------------------------------------------------------
// Saved filter presets
// ---------------------------------------------------------------------------

export interface FilterPreset {
  id: string;
  name: string;
  filters: ActivityFilterState;
}

const STORAGE_KEY = 'quickex:activity_filter_presets';

export function loadPresets(): FilterPreset[] {
  if (typeof window === 'undefined') return [];
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    return JSON.parse(raw) as FilterPreset[];
  } catch {
    return [];
  }
}

export function savePreset(preset: FilterPreset): void {
  if (typeof window === 'undefined') return;
  const existing = loadPresets().filter((p) => p.id !== preset.id);
  localStorage.setItem(STORAGE_KEY, JSON.stringify([...existing, preset]));
}

export function deletePreset(id: string): void {
  if (typeof window === 'undefined') return;
  const remaining = loadPresets().filter((p) => p.id !== id);
  localStorage.setItem(STORAGE_KEY, JSON.stringify(remaining));
}

// ---------------------------------------------------------------------------
// URL query-param serialisation
// ---------------------------------------------------------------------------

/**
 * Serialise the active filters into a URLSearchParams string so the current
 * view can be bookmarked / shared via URL.
 */
export function filtersToParams(filters: ActivityFilterState): URLSearchParams {
  const p = new URLSearchParams();
  if (filters.query)                           p.set('q',          filters.query);
  if (filters.status && filters.status !== 'All') p.set('status',  filters.status);
  if (filters.asset  && filters.asset  !== 'All') p.set('asset',   filters.asset);
  if (filters.dateFrom)                        p.set('dateFrom',   filters.dateFrom);
  if (filters.dateTo)                          p.set('dateTo',     filters.dateTo);
  if (filters.amountMin)                       p.set('amountMin',  filters.amountMin);
  if (filters.amountMax)                       p.set('amountMax',  filters.amountMax);
  if (filters.memo)                            p.set('memo',       filters.memo);
  return p;
}

/**
 * Parse URL search params back into an ActivityFilterState.
 * Unknown / malformed values fall back to defaults.
 */
export function paramsToFilters(params: URLSearchParams): ActivityFilterState {
  const status = params.get('status') as ActivityFilterStatus | null;
  return {
    query:      params.get('q')         ?? '',
    status:     status === 'Settled' || status === 'Pending' ? status : 'All',
    asset:      params.get('asset')     ?? 'All',
    dateFrom:   params.get('dateFrom')  ?? undefined,
    dateTo:     params.get('dateTo')    ?? undefined,
    amountMin:  params.get('amountMin') ?? undefined,
    amountMax:  params.get('amountMax') ?? undefined,
    memo:       params.get('memo')      ?? undefined,
  };
}

// ---------------------------------------------------------------------------
// Filter predicate
// ---------------------------------------------------------------------------

export function filterActivityItems(
  items: ActivityFeedItem[],
  filters: ActivityFilterState,
): ActivityFeedItem[] {
  const query       = filters.query.trim().toLowerCase();
  const assetFilter = (filters.asset ?? '').trim();
  const memoFilter  = (filters.memo  ?? '').trim().toLowerCase();

  const dateFromMs = filters.dateFrom
    ? new Date(filters.dateFrom).setHours(0, 0, 0, 0)
    : null;
  const dateToMs = filters.dateTo
    ? new Date(filters.dateTo).setHours(23, 59, 59, 999)
    : null;

  const amountMin = filters.amountMin ? parseFloat(filters.amountMin) : null;
  const amountMax = filters.amountMax ? parseFloat(filters.amountMax) : null;

  return items.filter((item) => {
    // --- Status ---
    if (filters.status !== 'All' && item.status !== filters.status) return false;

    // --- Asset ---
    if (assetFilter !== '' && assetFilter !== 'All') {
      if (item.asset.toLowerCase() !== assetFilter.toLowerCase()) return false;
    }

    // --- Date range ---
    if (dateFromMs !== null || dateToMs !== null) {
      const itemMs = item.timestamp ? new Date(item.timestamp).getTime() : NaN;
      if (isNaN(itemMs)) return false;
      if (dateFromMs !== null && itemMs < dateFromMs) return false;
      if (dateToMs   !== null && itemMs > dateToMs)   return false;
    }

    // --- Amount range ---
    if (amountMin !== null || amountMax !== null) {
      const val = parseFloat(item.amount);
      if (isNaN(val)) return false;
      if (amountMin !== null && val < amountMin) return false;
      if (amountMax !== null && val > amountMax) return false;
    }

    // --- Memo field ---
    if (memoFilter) {
      const itemMemo = (item.memo ?? '').toLowerCase();
      if (!itemMemo.includes(memoFilter)) return false;
    }

    // --- Full-text query (tx hash, counterparty addresses, amount, asset) ---
    if (query) {
      const searchable = [
        item.id,
        item.amount,
        item.asset,
        item.memo ?? '',
        item.source,
        item.destination,
        item.status,
      ]
        .join(' ')
        .toLowerCase();

      if (!searchable.includes(query)) return false;
    }

    return true;
  });
}

// ---------------------------------------------------------------------------
// Export helpers
// ---------------------------------------------------------------------------

/**
 * Convert a list of filtered items to a CSV string.
 * Exported columns: Date, Amount, Asset, Status, From, To, Memo, TX Hash
 */
export function exportToCsv(items: ActivityFeedItem[]): string {
  const HEADERS = ['Date', 'Amount', 'Asset', 'Status', 'From', 'To', 'Memo', 'TX Hash'];
  const escape = (val: string | null | undefined): string => {
    const s = val ?? '';
    // Wrap in quotes if it contains comma, quote, or newline
    if (/[",\n]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
    return s;
  };

  const rows = items.map((item) =>
    [
      escape(item.timestamp || item.date),
      escape(item.amount),
      escape(item.asset),
      escape(item.status),
      escape(item.source),
      escape(item.destination),
      escape(item.memo),
      escape(item.id),
    ].join(','),
  );

  return [HEADERS.join(','), ...rows].join('\n');
}

/**
 * Trigger a browser download of the CSV string.
 */
export function downloadCsv(items: ActivityFeedItem[], filename = 'transactions.csv'): void {
  const csv  = exportToCsv(items);
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href     = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

/**
 * Trigger a browser print-to-PDF of the filtered items.
 * Renders a minimal, print-optimised HTML table in a new window.
 */
export function printToPdf(items: ActivityFeedItem[], title = 'Transaction History'): void {
  const rows = items
    .map(
      (item) => `<tr>
        <td>${item.timestamp ? new Date(item.timestamp).toLocaleString() : item.date}</td>
        <td>${item.amount} ${item.asset}</td>
        <td>${item.status}</td>
        <td style="font-size:11px;word-break:break-all">${item.source}</td>
        <td style="font-size:11px;word-break:break-all">${item.destination}</td>
        <td>${item.memo ?? ''}</td>
        <td style="font-size:11px;word-break:break-all">${item.id}</td>
      </tr>`,
    )
    .join('');

  const html = `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>${title}</title>
  <style>
    body { font-family: sans-serif; font-size: 13px; color: #111; }
    h1   { font-size: 18px; margin-bottom: 8px; }
    table { width: 100%; border-collapse: collapse; margin-top: 12px; }
    th, td { border: 1px solid #ccc; padding: 6px 8px; text-align: left; }
    th { background: #f4f4f4; font-weight: 700; }
    @media print { body { margin: 0; } }
  </style>
</head>
<body>
  <h1>${title}</h1>
  <p>Exported on ${new Date().toLocaleString()} — ${items.length} transaction(s)</p>
  <table>
    <thead><tr>
      <th>Date</th><th>Amount</th><th>Status</th>
      <th>From</th><th>To</th><th>Memo</th><th>TX Hash</th>
    </tr></thead>
    <tbody>${rows}</tbody>
  </table>
</body>
</html>`;

  const win = window.open('', '_blank');
  if (win) {
    win.document.write(html);
    win.document.close();
    win.focus();
    win.print();
  }
}

// ---------------------------------------------------------------------------
// Utility: check if any non-default filter is active
// ---------------------------------------------------------------------------

export function hasActiveFilters(filters: ActivityFilterState): boolean {
  return (
    filters.query.trim().length > 0 ||
    (filters.status !== 'All' && Boolean(filters.status)) ||
    (filters.asset  !== 'All' && Boolean(filters.asset)) ||
    Boolean(filters.dateFrom) ||
    Boolean(filters.dateTo) ||
    Boolean(filters.amountMin) ||
    Boolean(filters.amountMax) ||
    Boolean(filters.memo?.trim())
  );
}
