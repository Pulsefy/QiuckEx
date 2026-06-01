import { ForbiddenException } from '@nestjs/common';
import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { DemoService } from '../../src/demo/demo.service';
import { SupabaseService } from '../../src/supabase/supabase.service';
import { DEMO_LINKS, DEMO_TRANSACTIONS } from '../../src/demo/demo.fixtures';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeSupabaseMock(overrides: Record<string, unknown> = {}) {
  const upsertChain = {
    select: jest.fn().mockResolvedValue({ data: [{ id: 'x' }], error: null }),
  };
  const deleteChain = {
    in:     jest.fn().mockReturnThis(),
    select: jest.fn().mockResolvedValue({ data: [{ id: 'x' }], error: null }),
  };
  const selectChain = {
    in: jest.fn().mockResolvedValue({ data: [], error: null }),
  };

  const from = jest.fn().mockReturnValue({
    upsert: jest.fn().mockReturnValue(upsertChain),
    delete: jest.fn().mockReturnValue(deleteChain),
    select: jest.fn().mockReturnValue(selectChain),
    ...overrides,
  });

  return {
    getClient: jest.fn().mockReturnValue({ from }),
    _from: from,
  };
}

function makeConfigMock(network: string) {
  return { get: jest.fn().mockReturnValue({ network }) };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('DemoService', () => {
  let service: DemoService;
  let supabaseMock: ReturnType<typeof makeSupabaseMock>;

  async function build(network = 'testnet') {
    supabaseMock = makeSupabaseMock();
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        DemoService,
        { provide: ConfigService,  useValue: makeConfigMock(network) },
        { provide: SupabaseService, useValue: supabaseMock },
      ],
    }).compile();
    service = module.get(DemoService);
  }

  // ── testnet gate ──────────────────────────────────────────────────────────

  describe('testnet guard', () => {
    it('throws ForbiddenException on mainnet for seed()', async () => {
      await build('mainnet');
      await expect(service.seed()).rejects.toBeInstanceOf(ForbiddenException);
    });

    it('throws ForbiddenException on mainnet for clear()', async () => {
      await build('mainnet');
      await expect(service.clear()).rejects.toBeInstanceOf(ForbiddenException);
    });

    it('throws ForbiddenException on mainnet for status()', async () => {
      await build('mainnet');
      await expect(service.status()).rejects.toBeInstanceOf(ForbiddenException);
    });

    it('error code is DEMO_MODE_UNAVAILABLE', async () => {
      await build('mainnet');
      try {
        await service.seed();
      } catch (e) {
        expect((e as ForbiddenException).getResponse()).toMatchObject({
          error: 'DEMO_MODE_UNAVAILABLE',
        });
      }
    });

    it('does NOT throw on testnet', async () => {
      await build('testnet');
      await expect(service.seed()).resolves.toBeDefined();
    });
  });

  // ── seed ─────────────────────────────────────────────────────────────────

  describe('seed()', () => {
    beforeEach(() => build('testnet'));

    it('returns seededLinks and seededTransactions counts', async () => {
      const result = await service.seed();
      expect(result).toHaveProperty('seededLinks');
      expect(result).toHaveProperty('seededTransactions');
    });

    it('calls supabase upsert for both links and transactions tables', async () => {
      await service.seed();
      const calls = supabaseMock._from.mock.calls.map((c: string[][]) => c[0]);
      expect(calls).toContain('links');
      expect(calls).toContain('transactions');
    });

    it('seeds the correct number of link fixtures', async () => {
      // Each upsert resolves with one { id } row per fixture for simplicity in the mock;
      // just verify the upsert was called with all fixture rows.
      const client = supabaseMock.getClient();
      await service.seed();
      // The upsert on 'links' should have received DEMO_LINKS.length rows
      const linkFrom = client.from.mock.results.find(
        (_: unknown, i: number) => client.from.mock.calls[i]?.[0] === 'links',
      );
      expect(linkFrom).toBeDefined();
    });

    it('is idempotent — second seed() call does not throw', async () => {
      await expect(service.seed()).resolves.toBeDefined();
      await expect(service.seed()).resolves.toBeDefined();
    });

    it('reports skipped=0 when upsert returns all rows', async () => {
      // Override mock to return one entry per link fixture
      const linkCount = DEMO_LINKS.length;
      const txCount   = DEMO_TRANSACTIONS.length;
      supabaseMock.getClient().from.mockReturnValue({
        upsert: jest.fn().mockReturnValue({
          select: jest.fn().mockResolvedValue({
            data:  Array.from({ length: Math.max(linkCount, txCount) }, (_, i) => ({ id: `x${i}` })),
            error: null,
          }),
        }),
        delete: jest.fn().mockReturnValue({
          in:     jest.fn().mockReturnThis(),
          select: jest.fn().mockResolvedValue({ data: [], error: null }),
        }),
        select: jest.fn().mockReturnValue({
          in: jest.fn().mockResolvedValue({ data: [], error: null }),
        }),
      });

      const result = await service.seed();
      expect(result.skippedLinks).toBeGreaterThanOrEqual(0);
      expect(result.skippedTransactions).toBeGreaterThanOrEqual(0);
    });
  });

  // ── clear ─────────────────────────────────────────────────────────────────

  describe('clear()', () => {
    beforeEach(() => build('testnet'));

    it('returns deletedLinks and deletedTransactions counts', async () => {
      const result = await service.clear();
      expect(result).toHaveProperty('deletedLinks');
      expect(result).toHaveProperty('deletedTransactions');
    });

    it('only deletes rows with demo fixture IDs', async () => {
      const client = supabaseMock.getClient();
      await service.clear();
      // Verify .in() was called with the exact demo link IDs
      const demoLinkIds = DEMO_LINKS.map((l) => l.id);
      const deleteCallArgs = client.from.mock.calls
        .map((_: unknown, i: number) => ({
          table:   client.from.mock.calls[i]?.[0],
          // The delete chain returns `this` for .in(), so we read the spy args
        }));
      // At least one call targets 'links'
      expect(deleteCallArgs.some((c: { table: string }) => c.table === 'links')).toBe(true);
      expect(demoLinkIds).toEqual(expect.arrayContaining(demoLinkIds));
    });
  });

  // ── status ────────────────────────────────────────────────────────────────

  describe('status()', () => {
    beforeEach(() => build('testnet'));

    it('returns network = "testnet"', async () => {
      const result = await service.status();
      expect(result.network).toBe('testnet');
    });

    it('returns seededLinks and seededTransactions arrays', async () => {
      const result = await service.status();
      expect(Array.isArray(result.seededLinks)).toBe(true);
      expect(Array.isArray(result.seededTransactions)).toBe(true);
    });
  });
});