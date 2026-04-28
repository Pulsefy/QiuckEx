/**
 * Cursor utility for cursor-based pagination.
 *
 * Cursors are opaque base64-encoded JSON strings that encode the sort key
 * values of the last row returned.  This makes pagination deterministic:
 * even if rows are inserted or deleted between requests the client will
 * neither skip nor duplicate rows.
 *
 * A cursor always includes the `id` column as a tiebreaker so the sort
 * is fully deterministic even when the primary sort column has duplicates.
 */

export interface CursorPayload {
  /** Value of the primary sort column of the last returned row */
  pk: string;
  /** UUID id of the last returned row – tiebreaker */
  id: string;
}

/**
 * Encode a cursor payload to an opaque base64 string safe for URLs.
 */
export function encodeCursor(payload: CursorPayload): string {
  const json = JSON.stringify(payload);
  return Buffer.from(json, 'utf-8').toString('base64url');
}

/**
 * Decode an opaque cursor string back to its payload.
 * Returns `null` when the cursor is invalid or malformed.
 */
export function decodeCursor(cursor: string): CursorPayload | null {
  try {
    const json = Buffer.from(cursor, 'base64url').toString('utf-8');
    const parsed = JSON.parse(json);
    if (typeof parsed.pk === 'string' && typeof parsed.id === 'string') {
      return parsed as CursorPayload;
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Default page sizes used across the application.
 */
export const PAGINATION_DEFAULTS = {
  LIMIT_MIN: 1,
  LIMIT_MAX: 100,
  LIMIT_DEFAULT: 20,
} as const;

/**
 * Clamp a user-supplied limit value to the allowed range.
 */
export function clampLimit(
  limit: number | undefined,
  min: number = PAGINATION_DEFAULTS.LIMIT_MIN,
  max: number = PAGINATION_DEFAULTS.LIMIT_MAX,
  fallback: number = PAGINATION_DEFAULTS.LIMIT_DEFAULT,
): number {
  if (limit === undefined || limit === null || Number.isNaN(limit)) {
    return fallback;
  }
  return Math.min(max, Math.max(min, Math.floor(limit)));
}

/**
 * Build the Supabase query filter for cursor-based pagination.
 *
 * Strategy: we fetch `limit + 1` rows. If the extra row exists we know
 * there is a next page and we use its sort values as `next_cursor`.
 *
 * @param query - A Supabase query builder (already has `.select()` etc.)
 * @param cursor - Decoded cursor payload or undefined
 * @param orderColumn - The column used for ORDER BY (e.g. 'created_at')
 * @param ascending - Sort direction matching the ORDER BY
 */
export function applyCursorFilter<
  T extends {
    eq: (col: string, val: unknown) => T;
    lt: (col: string, val: string) => T;
    gt: (col: string, val: string) => T;
    order: (col: string, opts: { ascending: boolean }) => T;
    limit: (n: number) => T;
  },
>(query: T, cursor: CursorPayload | null, orderColumn: string, ascending: boolean, limit: number): T {
  const effectiveLimit = limit + 1; // fetch one extra to detect next page

  let q = query.order(orderColumn, { ascending });

  if (cursor) {
    // For DESC order: next page rows have (orderColumn < cursor.pk)
    //   OR (orderColumn = cursor.pk AND id < cursor.id)
    // For ASC order: next page rows have (orderColumn > cursor.pk)
    //   OR (orderColumn = cursor.pk AND id > cursor.id)
    if (ascending) {
      q = q.gt(orderColumn, cursor.pk).order('id', { ascending: true }).gt('id', cursor.id) as T;
    } else {
      q = q.lt(orderColumn, cursor.pk).order('id', { ascending: false }).lt('id', cursor.id) as T;
    }
  }

  // Deterministic tiebreaker by id
  q = q.order('id', { ascending }).limit(effectiveLimit) as T;

  return q;
}

/**
 * Given the rows fetched (which may be limit+1) and the order column name,
 * split them into the actual page and compute the next cursor.
 */
export function paginateResult<T>(
  rows: T[],
  limit: number,
  orderColumn: string,
): { data: T[]; next_cursor: string | null; has_more: boolean } {
  const hasMore = rows.length > limit;
  const data = hasMore ? rows.slice(0, limit) : rows;

  let nextCursor: string | null = null;
  if (hasMore && data.length > 0) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const last = data[data.length - 1] as any;
    nextCursor = encodeCursor({
      pk: String(last[orderColumn]),
      id: String(last['id']),
    });
  }

  return { data, next_cursor: nextCursor, has_more: hasMore };
}
