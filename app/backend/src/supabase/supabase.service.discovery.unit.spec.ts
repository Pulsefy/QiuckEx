import { Test } from '@nestjs/testing';
import { createClient } from '@supabase/supabase-js';
import { SupabaseService } from './supabase.service';
import { AppConfigService } from '../config';

// Mock the supabase-js module
jest.mock('@supabase/supabase-js', () => ({
  createClient: jest.fn(),
}));

/**
 * Builds a chainable, awaitable Supabase query-builder stand-in. Every
 * filter/order/limit method returns the chain itself so calls can be
 * composed in any order (matching real supabase-js), and `await`-ing the
 * chain at any point resolves to `result` (matching PostgrestFilterBuilder's
 * thenable behavior).
 */
function makeChain(result: { data?: unknown; error?: unknown }) {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const chain: any = {};
  ['select', 'eq', 'gte', 'in', 'ilike', 'order', 'limit'].forEach((method) => {
    chain[method] = jest.fn(() => chain);
  });
  chain.then = (
    resolve: (value: typeof result) => unknown,
    reject: (reason: unknown) => unknown,
  ) => Promise.resolve(result).then(resolve, reject);
  return chain;
}

/**
 * Routes `.from(table)` calls to a queue of pre-built chains, consumed in
 * call order. This supports methods that query the same table more than
 * once (e.g. `getRecentlyActiveUsers` queries `usernames` twice) with
 * different results per call.
 */
function makeClient(routes: Record<string, ReturnType<typeof makeChain>[]>) {
  return {
    from: jest.fn((table: string) => {
      const queue = routes[table];
      if (!queue || queue.length === 0) {
        throw new Error(`Unexpected call to from('${table}')`);
      }
      return queue.shift();
    }),
  };
}

/**
 * Builds a fresh SupabaseService bound to the given mock client. A fresh
 * module is required per test because the client is captured once, in the
 * constructor.
 */
async function createService(
  client: ReturnType<typeof makeClient>,
): Promise<SupabaseService> {
  (createClient as jest.Mock).mockReturnValue(client);
  const module = await Test.createTestingModule({
    providers: [
      SupabaseService,
      {
        provide: AppConfigService,
        useValue: { supabaseUrl: 'http://localhost:54321', supabaseAnonKey: 'anon-key' },
      },
    ],
  }).compile();
  return module.get<SupabaseService>(SupabaseService);
}

describe('SupabaseService discovery ranking', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('getFeaturedUsernames', () => {
    it('queries public + featured profiles ordered by featured_rank asc (nulls last), id asc', async () => {
      const profiles = [
        { id: 'id-1', username: 'a', public_key: 'GAAA1', created_at: '2025-01-01T00:00:00.000Z', last_active_at: null, is_public: true, featured_rank: 1 },
      ];
      const usernamesChain = makeChain({ data: profiles, error: null });
      const service = await createService(makeClient({ usernames: [usernamesChain] }));

      const result = await service.getFeaturedUsernames(10);

      expect(result).toEqual(profiles);
      expect(usernamesChain.eq).toHaveBeenCalledWith('is_public', true);
      expect(usernamesChain.eq).toHaveBeenCalledWith('is_featured', true);
      expect(usernamesChain.order).toHaveBeenCalledWith('featured_rank', { ascending: true, nullsFirst: false });
      expect(usernamesChain.order).toHaveBeenCalledWith('id', { ascending: true });
      expect(usernamesChain.limit).toHaveBeenCalledWith(10);
    });
  });

  describe('getTrendingCreators', () => {
    it('does not drop lower-volume public creators just because a higher-volume non-public account exists', async () => {
      // "ghost" is the top earner by volume but has no public profile: it
      // must not consume a ranking slot ahead of public creators.
      const payments = [
        { sender_public_key: 'ghost', receiver_public_key: 'GBBB', amount_usd: 1000 },
        { sender_public_key: 'GBBB', receiver_public_key: 'GCCC', amount_usd: 500 },
        { sender_public_key: 'GCCC', receiver_public_key: 'GBBB', amount_usd: 100 },
      ];
      // Only public profiles are returned by the `.eq('is_public', true)` filter.
      const publicProfiles = [
        { id: 'id-b', username: 'b', public_key: 'GBBB', created_at: '2025-01-01T00:00:00.000Z', last_active_at: null, is_public: true },
        { id: 'id-c', username: 'c', public_key: 'GCCC', created_at: '2025-01-02T00:00:00.000Z', last_active_at: null, is_public: true },
      ];

      const service = await createService(
        makeClient({
          payment_records: [makeChain({ data: payments, error: null })],
          usernames: [makeChain({ data: publicProfiles, error: null })],
        }),
      );

      // limit=2: with the bug, "ghost" would occupy a ranking slot and get
      // filtered out afterward, leaving only 1 result instead of 2.
      const result = await service.getTrendingCreators(24, 2);

      expect(result.map((r) => r.username)).toEqual(['b', 'c']);
      expect(result[0].transaction_volume).toBeGreaterThan(result[1].transaction_volume);
    });

    it('breaks equal-volume ties deterministically by ascending id', async () => {
      const payments = [
        { sender_public_key: 'GAAA2', receiver_public_key: 'GAAA3', amount_usd: 200 },
      ];
      const publicProfiles = [
        { id: 'id-3', username: 'c', public_key: 'GAAA3', created_at: '2025-01-01T00:00:00.000Z', last_active_at: null, is_public: true },
        { id: 'id-2', username: 'b', public_key: 'GAAA2', created_at: '2025-01-01T00:00:00.000Z', last_active_at: null, is_public: true },
      ];

      const service = await createService(
        makeClient({
          payment_records: [makeChain({ data: payments, error: null })],
          usernames: [makeChain({ data: publicProfiles, error: null })],
        }),
      );

      const result = await service.getTrendingCreators(24, 10);

      // Both GAAA2 and GAAA3 accrue equal volume (200) from the same payment.
      expect(result[0].transaction_volume).toBe(result[1].transaction_volume);
      expect(result.map((r) => r.id)).toEqual(['id-2', 'id-3']);
    });
  });

  describe('getRecentlyActiveUsers', () => {
    it('ranks by merged payment activity, not the stale DB last_active_at column, and never truncates the profile fetch at the DB layer', async () => {
      // Two separate payments give GAAA1 and GAAA2 different payment-derived
      // activity timestamps, even though their `usernames.last_active_at`
      // columns (below) are identical and stale.
      const payments = [
        { sender_public_key: 'GAAA1', receiver_public_key: 'GAAA9', created_at: '2025-06-01T00:00:00.000Z' },
        { sender_public_key: 'GAAA9', receiver_public_key: 'GAAA2', created_at: '2025-01-15T00:00:00.000Z' },
      ];
      const profileActivityRows: unknown[] = [];
      const profiles = [
        { id: 'id-1', username: 'a', public_key: 'GAAA1', created_at: '2025-01-01T00:00:00.000Z', last_active_at: '2025-01-01T00:00:00.000Z', is_public: true },
        { id: 'id-2', username: 'b', public_key: 'GAAA2', created_at: '2025-01-01T00:00:00.000Z', last_active_at: '2025-01-01T00:00:00.000Z', is_public: true },
      ];

      const usernamesProfilesChain = makeChain({ data: profiles, error: null });
      const service = await createService(
        makeClient({
          payment_records: [makeChain({ data: payments, error: null })],
          usernames: [makeChain({ data: profileActivityRows, error: null }), usernamesProfilesChain],
        }),
      );

      const result = await service.getRecentlyActiveUsers(720, 10);

      // GAAA1's payment-derived timestamp (2025-06-01) is more recent than
      // GAAA2's (2025-01-15), so it must rank first despite both profiles
      // sharing the same stale `last_active_at` column value.
      expect(result.map((r) => r.username)).toEqual(['a', 'b']);
      // The final profiles fetch must not be limited at the DB layer, since
      // ranking depends on the in-memory merge with payment activity -
      // truncating there could silently drop the true top-N candidates.
      expect(usernamesProfilesChain.limit).not.toHaveBeenCalled();
    });

    it('breaks equal-activity ties deterministically by ascending id', async () => {
      const payments: unknown[] = [];
      const profileActivityRows = [{ public_key: 'GAAA2' }, { public_key: 'GAAA3' }];
      const profiles = [
        { id: 'id-3', username: 'c', public_key: 'GAAA3', created_at: '2025-01-01T00:00:00.000Z', last_active_at: '2025-01-05T00:00:00.000Z', is_public: true },
        { id: 'id-2', username: 'b', public_key: 'GAAA2', created_at: '2025-01-01T00:00:00.000Z', last_active_at: '2025-01-05T00:00:00.000Z', is_public: true },
      ];

      const service = await createService(
        makeClient({
          payment_records: [makeChain({ data: payments, error: null })],
          usernames: [
            makeChain({ data: profileActivityRows, error: null }),
            makeChain({ data: profiles, error: null }),
          ],
        }),
      );

      const result = await service.getRecentlyActiveUsers(24, 10);

      expect(result.map((r) => r.id)).toEqual(['id-2', 'id-3']);
    });
  });
});
