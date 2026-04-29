import { encodeCursor, decodeCursor, clampLimit, paginateResult, PAGINATION_DEFAULTS } from './cursor.util';

describe('Cursor Utility', () => {
  describe('encodeCursor / decodeCursor', () => {
    it('round-trips a valid cursor payload', () => {
      const payload = { pk: '2026-01-01T00:00:00.000Z', id: '1234-5678-abcd' };
      const encoded = encodeCursor(payload);
      const decoded = decodeCursor(encoded);
      expect(decoded).toEqual(payload);
    });

    it('produces URL-safe base64 (no +/= characters)', () => {
      const payload = { pk: '2026-01-01T00:00:00.000Z', id: 'abc==test+data/here' };
      const encoded = encodeCursor(payload);
      expect(encoded).not.toMatch(/[+/=]/);
    });

    it('returns null for an invalid base64 string', () => {
      expect(decodeCursor('not-valid-base64!!!')).toBeNull();
    });

    it('returns null for valid base64 but wrong JSON shape', () => {
      const json = JSON.stringify({ wrong: 'shape' });
      const encoded = Buffer.from(json, 'utf-8').toString('base64url');
      expect(decodeCursor(encoded)).toBeNull();
    });

    it('returns null for empty string', () => {
      expect(decodeCursor('')).toBeNull();
    });
  });

  describe('clampLimit', () => {
    it('returns default when limit is undefined', () => {
      expect(clampLimit(undefined)).toBe(PAGINATION_DEFAULTS.LIMIT_DEFAULT);
    });

    it('clamps to minimum when below range', () => {
      expect(clampLimit(0)).toBe(PAGINATION_DEFAULTS.LIMIT_MIN);
      expect(clampLimit(-5)).toBe(PAGINATION_DEFAULTS.LIMIT_MIN);
    });

    it('clamps to maximum when above range', () => {
      expect(clampLimit(500)).toBe(PAGINATION_DEFAULTS.LIMIT_MAX);
    });

    it('returns the value when in range', () => {
      expect(clampLimit(50)).toBe(50);
    });

    it('floors decimal values', () => {
      expect(clampLimit(20.9)).toBe(20);
    });

    it('handles NaN by returning default', () => {
      expect(clampLimit(Number.NaN)).toBe(PAGINATION_DEFAULTS.LIMIT_DEFAULT);
    });

    it('uses custom min/max/fallback', () => {
      expect(clampLimit(undefined, 5, 50, 25)).toBe(25);
      expect(clampLimit(3, 5, 50, 25)).toBe(5);
      expect(clampLimit(60, 5, 50, 25)).toBe(50);
    });
  });

  describe('paginateResult', () => {
    const makeRow = (id: string, createdAt: string) => ({ id, created_at: createdAt });

    it('returns all rows when count <= limit', () => {
      const rows = [makeRow('1', '2026-01-01'), makeRow('2', '2026-01-02')];
      const result = paginateResult(rows, 5, 'created_at');
      expect(result.data).toEqual(rows);
      expect(result.next_cursor).toBeNull();
      expect(result.has_more).toBe(false);
    });

    it('truncates to limit and sets has_more=true when count > limit', () => {
      const rows = [makeRow('1', '2026-01-01'), makeRow('2', '2026-01-02'), makeRow('3', '2026-01-03')];
      const result = paginateResult(rows, 2, 'created_at');
      expect(result.data).toEqual([rows[0], rows[1]]);
      expect(result.has_more).toBe(true);
    });

    it('produces a valid next_cursor from the last row', () => {
      const rows = [makeRow('1', '2026-01-01'), makeRow('2', '2026-01-02'), makeRow('3', '2026-01-03')];
      const result = paginateResult(rows, 2, 'created_at');
      expect(result.next_cursor).not.toBeNull();
      const decoded = decodeCursor(result.next_cursor!);
      expect(decoded).toEqual({ pk: '2026-01-02', id: '2' });
    });

    it('returns no duplicates across pages (simulated pagination)', () => {
      // Rows in DESC order as returned by the database
      const allRows = [
        makeRow('5', '2026-01-05'),
        makeRow('4', '2026-01-04'),
        makeRow('3', '2026-01-03'),
        makeRow('2', '2026-01-02'),
        makeRow('1', '2026-01-01'),
      ];

      // Page 1
      const page1 = paginateResult(allRows.slice(0, 3), 2, 'created_at');
      expect(page1.data).toHaveLength(2);
      expect(page1.has_more).toBe(true);

      // Page 2: use cursor from page 1
      const cursor = decodeCursor(page1.next_cursor!);
      expect(cursor).not.toBeNull();

      const remaining = allRows.filter(
        (r) => r.created_at < cursor!.pk || (r.created_at === cursor!.pk && r.id < cursor!.id),
      );
      const page2 = paginateResult(remaining.slice(0, 3), 2, 'created_at');
      expect(page2.data).toHaveLength(2);
      expect(page2.has_more).toBe(true);

      // Verify no overlap
      const page1Ids = page1.data.map((r) => r.id);
      const page2Ids = page2.data.map((r) => r.id);
      const overlap = page1Ids.filter((id) => page2Ids.includes(id));
      expect(overlap).toHaveLength(0);
    });

    it('returns empty data and null cursor for empty input', () => {
      const result = paginateResult([], 10, 'created_at');
      expect(result.data).toEqual([]);
      expect(result.next_cursor).toBeNull();
      expect(result.has_more).toBe(false);
    });

    it('covers all rows with no skips (complete pagination walk)', () => {
      // Rows in DESC order as returned by the database
      const allRows = Array.from({ length: 7 }, (_, i) =>
        makeRow(`id-${7 - i}`, `2026-01-0${7 - i}`),
      );

      const collectedIds: string[] = [];
      let remaining = [...allRows];

      // Paginate through all rows
      for (let page = 0; page < 10; page++) {
        if (remaining.length === 0) break;

        const pageRows = remaining.slice(0, 4); // limit=3, fetch limit+1=4
        const result = paginateResult(pageRows, 3, 'created_at');

        collectedIds.push(...result.data.map((r) => r.id));

        if (!result.has_more) break;

        const cursor = decodeCursor(result.next_cursor!);
        remaining = remaining.filter(
          (r) => r.created_at < cursor!.pk || (r.created_at === cursor!.pk && r.id < cursor!.id),
        );
      }

      // All 7 rows collected, no duplicates, no skips
      const allIds = allRows.map((r) => r.id);
      expect(collectedIds).toEqual(allIds);
      expect(new Set(collectedIds).size).toBe(collectedIds.length);
    });
  });
});
