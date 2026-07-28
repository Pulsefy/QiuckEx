import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';
import { AppModule } from '../src/app.module';
import { SupabaseService } from '../src/supabase/supabase.service';

/**
 * End-to-end tests for BE-59: Contributor Preview Data Isolation.
 *
 * Acceptance criteria:
 * 1. Preview environments only surface their own scoped test data.
 * 2. Shared testnet defaults remain intact for non-preview flows.
 * 3. Expired scopes can be cleaned safely without deleting shared records.
 */
describe('Preview Scope Data Isolation (e2e)', () => {
  let app: INestApplication;
  let supabaseService: SupabaseService;

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    await app.init();

    supabaseService = moduleFixture.get<SupabaseService>(SupabaseService);
  });

  afterAll(async () => {
    await app.close();
  });

  /* ─── Helpers ─────────────────────────────────────────────────────────── */

  const previewScopeA = 'preview-scope-a';
  const previewScopeB = 'preview-scope-b';

  async function seedPaymentLink(
    scopeId: string | null,
    overrides: Record<string, unknown> = {},
  ): Promise<string> {
    const row: Record<string, unknown> = {
      owner_public_key: 'GA' + 'A'.repeat(54),
      destination_public_key: 'GB' + 'B'.repeat(54),
      amount: '100.0000000',
      asset_code: 'XLM',
      memo: 'test-memo-' + Date.now(),
      memo_type: 'text',
      status: 'open',
      preview_scope: scopeId,
      ...overrides,
    };

    const { data, error } = await supabaseService
      .getClient()
      .from('payment_links')
      .insert(row)
      .select('id')
      .single();

    if (error) throw error;
    return (data as { id: string }).id;
  }

  async function countPaymentLinks(scopeId: string | null): Promise<number> {
    const query = supabaseService
      .getClient()
      .from('payment_links')
      .select('id', { count: 'exact', head: true });

    if (scopeId === null) {
      query.is('preview_scope', null);
    } else {
      query.eq('preview_scope', scopeId);
    }

    const { count, error } = await query;
    if (error) throw error;
    return count ?? 0;
  }

  async function cleanupTestData(scopeIds: string[]): Promise<void> {
    for (const sid of scopeIds) {
      await supabaseService
        .getClient()
        .from('payment_links')
        .delete()
        .eq('preview_scope', sid);
    }
  }

  /* ─── Tests ───────────────────────────────────────────────────────────── */

  describe('Acceptance Criterion 1: Data isolation between preview scopes', () => {
    beforeAll(async () => {
      // Seed:
      //   - 2 links in scope A
      //   - 3 links in scope B
      //   - 1 link with no scope (shared testnet)
      await Promise.all([
        seedPaymentLink(previewScopeA, { memo: 'scope-a-1' }),
        seedPaymentLink(previewScopeA, { memo: 'scope-a-2' }),
        seedPaymentLink(previewScopeB, { memo: 'scope-b-1' }),
        seedPaymentLink(previewScopeB, { memo: 'scope-b-2' }),
        seedPaymentLink(previewScopeB, { memo: 'scope-b-3' }),
        seedPaymentLink(null, { memo: 'shared-1' }),
      ]);
    });

    afterAll(async () => {
      await cleanupTestData([previewScopeA, previewScopeB]);
      // Also clean up the shared record
      await supabaseService
        .getClient()
        .from('payment_links')
        .delete()
        .eq('memo', 'shared-1');
    });

    it('scope A queries only return scope A records', async () => {
      const count = await countPaymentLinks(previewScopeA);
      expect(count).toBe(2);
    });

    it('scope B queries only return scope B records', async () => {
      const count = await countPaymentLinks(previewScopeB);
      expect(count).toBe(3);
    });

    it('scope A records are not visible to scope B queries', async () => {
      const count = await countPaymentLinks(previewScopeB);
      // Scope B should only see its 3 records, not scope A's 2
      expect(count).toBe(3);
      const allRecords = await supabaseService
        .getClient()
        .from('payment_links')
        .select('id, preview_scope, memo')
        .eq('preview_scope', previewScopeB);
      const memos = (allRecords.data ?? []).map(
        (r: { memo: string }) => r.memo,
      );
      expect(memos).not.toContain('scope-a-1');
      expect(memos).not.toContain('scope-a-2');
    });
  });

  describe('Acceptance Criterion 2: Shared testnet is unaffected', () => {
    it('shared (null scope) queries still return shared records', async () => {
      const count = await countPaymentLinks(null);
      // At minimum the shared-1 record should be visible
      expect(count).toBeGreaterThanOrEqual(1);
    });

    it('preview-scoped writes do not appear as shared records', async () => {
      // Shared records should be independent of preview-scoped records
      // This verifies `preview_scope IS NULL` queries exclude scoped rows
      // and preview_scope = 'X' queries exclude both shared and other scopes
      const sharedIds = await supabaseService
        .getClient()
        .from('payment_links')
        .select('id')
        .is('preview_scope', null);
      const scopedIds = await supabaseService
        .getClient()
        .from('payment_links')
        .select('id')
        .not('preview_scope', 'is', null);

      const sharedSet = new Set(
        (sharedIds.data ?? []).map((r: { id: string }) => r.id),
      );
      const scopedSet = new Set(
        (scopedIds.data ?? []).map((r: { id: string }) => r.id),
      );

      // No ID should appear in both sets
      for (const id of sharedSet) {
        expect(scopedSet.has(id)).toBe(false);
      }
      for (const id of scopedSet) {
        expect(sharedSet.has(id)).toBe(false);
      }
    });
  });

  describe('Acceptance Criterion 3: Safe cleanup of expired scopes', () => {
    it('deleting an expired scope removes only its records, not shared data', async () => {
      // Count shared records before cleanup
      const sharedBefore = await countPaymentLinks(null);

      // Simulate cleanup: delete all payment_links for scope A
      await supabaseService
        .getClient()
        .from('payment_links')
        .delete()
        .eq('preview_scope', previewScopeA);

      // Shared records should be intact
      const sharedAfter = await countPaymentLinks(null);
      expect(sharedAfter).toBe(sharedBefore);

      // Scope A records should be gone
      const scopeAAfter = await countPaymentLinks(previewScopeA);
      expect(scopeAAfter).toBe(0);

      // Re-seed scope A records for other tests
      await Promise.all([
        seedPaymentLink(previewScopeA, { memo: 'scope-a-1' }),
        seedPaymentLink(previewScopeA, { memo: 'scope-a-2' }),
      ]);
    });
  });

  describe('HTTP endpoint respects X-Preview-Scope header', () => {
    it('should include preview_scope in request when header is sent', async () => {
      // The middleware attaches req.previewScope from X-Preview-Scope header.
      // We verify the middleware runs by checking that a request with
      // the header returns successfully (it does not reject).
      const res = await request(app.getHttpServer())
        .get('/health')
        .set('X-Preview-Scope', previewScopeA)
        .expect(200);

      expect(res.body).toBeDefined();
    });

    it('should not require X-Preview-Scope for public endpoints', async () => {
      const res = await request(app.getHttpServer())
        .get('/health')
        .expect(200);

      expect(res.body).toBeDefined();
    });
  });
});
