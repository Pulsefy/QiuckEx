import { Test, TestingModule } from '@nestjs/testing';
import { EventEmitter2 } from '@nestjs/event-emitter';

import { AutoMatchService } from './auto-match.service';
import { UnmatchedQueueRepository } from './unmatched-queue.repository';
import { AppConfigService } from '../config/app-config.service';
import { SupabaseService } from '../supabase/supabase.service';
import { MetricsService } from '../metrics/metrics.service';
import {
  IncomingTransaction,
  MatchDecision,
  PaymentLink,
  PaymentLinkStatus,
} from './types/auto-match.types';

// ─── Fixtures ────────────────────────────────────────────────────────────────

const DESTINATION = 'GDESTINATION1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const SOURCE = 'GSOURCE1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ12345';

function makeTx(overrides: Partial<IncomingTransaction> = {}): IncomingTransaction {
  return {
    txHash: 'abc123def456abc123def456abc123def456abc123def456abc123def456abc123',
    ledger: 55000000,
    sourceAccount: SOURCE,
    destinationAccount: DESTINATION,
    amount: '10.0000000',
    assetCode: 'XLM',
    assetIssuer: null,
    memo: 'INV-001',
    memoType: 'text',
    occurredAt: '2026-04-29T10:00:00Z',
    ...overrides,
  };
}

function makeLink(overrides: Partial<PaymentLink> = {}): PaymentLink {
  return {
    id: 'link-uuid-0001',
    owner_public_key: DESTINATION,
    destination_public_key: DESTINATION,
    amount: '10.0000000',
    asset_code: 'XLM',
    asset_issuer: null,
    memo: 'INV-001',
    memo_type: 'text',
    reference_id: null,
    status: PaymentLinkStatus.Open,
    expires_at: null,
    matched_tx_hash: null,
    matched_at: null,
    match_confidence: null,
    created_at: '2026-04-28T08:00:00Z',
    updated_at: '2026-04-28T08:00:00Z',
    ...overrides,
  };
}

// ─── Mocks ────────────────────────────────────────────────────────────────────

const mockConfig = {
  network: 'testnet',
} as unknown as AppConfigService;

const mockSupabase = {
  getClient: jest.fn().mockReturnValue({
    from: jest.fn().mockReturnThis(),
    select: jest.fn().mockReturnThis(),
    update: jest.fn().mockReturnThis(),
    eq: jest.fn().mockReturnThis(),
    or: jest.fn().mockResolvedValue({ data: [], error: null }),
  }),
} as unknown as SupabaseService;

const mockMetrics = {
  recordExternalCall: jest.fn(),
  recordError: jest.fn(),
} as unknown as MetricsService;

const mockUnmatchedQueue = {
  enqueue: jest.fn().mockResolvedValue(null),
} as unknown as UnmatchedQueueRepository;

const mockEventEmitter = {
  emit: jest.fn(),
} as unknown as EventEmitter2;

// ─── Suite ────────────────────────────────────────────────────────────────────

describe('AutoMatchService', () => {
  let service: AutoMatchService;

  beforeEach(async () => {
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AutoMatchService,
        { provide: AppConfigService, useValue: mockConfig },
        { provide: SupabaseService, useValue: mockSupabase },
        { provide: MetricsService, useValue: mockMetrics },
        { provide: UnmatchedQueueRepository, useValue: mockUnmatchedQueue },
        { provide: EventEmitter2, useValue: mockEventEmitter },
      ],
    }).compile();

    service = module.get(AutoMatchService);
  });

  // ─── scoreOne ──────────────────────────────────────────────────────────────

  describe('scoreOne()', () => {
    describe('asset mismatch', () => {
      it('returns confidence 0 when asset codes differ', () => {
        const tx = makeTx({ assetCode: 'USDC', assetIssuer: 'GISSUER1' });
        const link = makeLink({ asset_code: 'XLM', asset_issuer: null });
        const counts = new Map<string, number>();

        const result = service.scoreOne(tx, link, counts);
        expect(result.confidence).toBe(0);
        expect(result.breakdown.assetMatches).toBe(false);
      });

      it('returns confidence 0 when issuers differ for the same asset code', () => {
        const tx = makeTx({ assetCode: 'USDC', assetIssuer: 'GISSUER_A' });
        const link = makeLink({ asset_code: 'USDC', asset_issuer: 'GISSUER_B' });
        const counts = new Map<string, number>();

        const result = service.scoreOne(tx, link, counts);
        expect(result.confidence).toBe(0);
      });
    });

    describe('unique memo + exact amount (100 % confidence path)', () => {
      it('returns confidence 100 when memo is unique and amount is exact', () => {
        const tx = makeTx();
        const link = makeLink();
        // Only one link carries this memo → unique
        const counts = new Map([['INV-001', 1]]);

        const result = service.scoreOne(tx, link, counts);
        expect(result.confidence).toBe(100);
        expect(result.breakdown.memoMatches).toBe(true);
        expect(result.breakdown.memoIsUnique).toBe(true);
        expect(result.breakdown.amountExact).toBe(true);
      });
    });

    describe('unique memo + amount mismatch (review threshold)', () => {
      it('returns confidence 60 (memo only) when amount does not match', () => {
        const tx = makeTx({ amount: '99.0000000' });
        const link = makeLink({ amount: '10.0000000' });
        const counts = new Map([['INV-001', 1]]);

        const result = service.scoreOne(tx, link, counts);
        expect(result.confidence).toBe(60);
        expect(result.breakdown.memoMatches).toBe(true);
        expect(result.breakdown.memoIsUnique).toBe(true);
        expect(result.breakdown.amountExact).toBe(false);
        expect(result.breakdown.amountWithinTolerance).toBe(false);
      });

      it('awards partial amount credit when within tolerance', () => {
        // Exact link: 10.0000000, tx: 10.0050000 (0.05% delta < 0.1% tolerance)
        const tx = makeTx({ amount: '10.0050000' });
        const link = makeLink({ amount: '10.0000000' });
        const counts = new Map([['INV-001', 1]]);

        const result = service.scoreOne(tx, link, counts);
        expect(result.confidence).toBe(80); // 60 (unique memo) + 20 (tolerance)
        expect(result.breakdown.amountWithinTolerance).toBe(true);
        expect(result.breakdown.amountExact).toBe(false);
      });
    });

    describe('non-unique memo + exact amount', () => {
      it('returns confidence 65 when memo matches but is shared by two links', () => {
        const tx = makeTx();
        const link = makeLink();
        // Two open links share the same memo
        const counts = new Map([['INV-001', 2]]);

        const result = service.scoreOne(tx, link, counts);
        expect(result.confidence).toBe(65); // 25 (non-unique) + 40 (exact amount)
        expect(result.breakdown.memoIsUnique).toBe(false);
      });
    });

    describe('memo mismatch hard exclusion', () => {
      it('returns confidence 0 when both sides have a memo but they differ', () => {
        const tx = makeTx({ memo: 'INV-999' });
        const link = makeLink({ memo: 'INV-001' });
        const counts = new Map([['INV-001', 1]]);

        const result = service.scoreOne(tx, link, counts);
        expect(result.confidence).toBe(0);
      });

      it('returns confidence 0 when link has memo but transaction does not', () => {
        const tx = makeTx({ memo: null, memoType: null });
        const link = makeLink({ memo: 'INV-001' });
        const counts = new Map([['INV-001', 1]]);

        const result = service.scoreOne(tx, link, counts);
        expect(result.confidence).toBe(0);
      });
    });

    describe('no memo on either side', () => {
      it('scores amount only when neither side has a memo', () => {
        const tx = makeTx({ memo: null, memoType: null });
        const link = makeLink({ memo: null });
        const counts = new Map<string, number>();

        const result = service.scoreOne(tx, link, counts);
        expect(result.confidence).toBe(40); // 0 (no memo) + 40 (exact amount)
        expect(result.breakdown.memoPresent).toBe(false);
        expect(result.breakdown.amountExact).toBe(true);
      });
    });

    describe('transaction has memo but link does not', () => {
      it('continues to amount scoring (no hard exclusion)', () => {
        const tx = makeTx({ memo: 'EXTRA-MEMO' });
        const link = makeLink({ memo: null });
        const counts = new Map<string, number>();

        const result = service.scoreOne(tx, link, counts);
        expect(result.confidence).toBe(40); // 0 (memo mismatch — no points) + 40 (exact)
      });
    });
  });

  // ─── scoreCandidates ───────────────────────────────────────────────────────

  describe('scoreCandidates()', () => {
    it('returns candidates sorted by confidence descending', () => {
      const tx = makeTx();
      const linkA = makeLink({ id: 'link-A', memo: 'INV-001' }); // unique → 100
      const linkB = makeLink({ id: 'link-B', memo: null });        // no memo → 40

      const result = service.scoreCandidates(tx, [linkB, linkA]);

      expect(result[0].link.id).toBe('link-A');
      expect(result[0].score.confidence).toBe(100);
      expect(result[1].link.id).toBe('link-B');
      expect(result[1].score.confidence).toBe(40);
    });

    it('excludes candidates with confidence 0', () => {
      const tx = makeTx({ assetCode: 'XLM' });
      const mismatchedLink = makeLink({ asset_code: 'USDC' }); // asset mismatch → 0

      const result = service.scoreCandidates(tx, [mismatchedLink]);
      expect(result).toHaveLength(0);
    });

    it('returns empty array when there are no open links', () => {
      const tx = makeTx();
      const result = service.scoreCandidates(tx, []);
      expect(result).toHaveLength(0);
    });
  });

  // ─── processTransaction ────────────────────────────────────────────────────

  describe('processTransaction()', () => {
    it('returns AutoMatch for a 100% confidence unique-memo + exact-amount match', async () => {
      const tx = makeTx();
      const link = makeLink();

      // Mock the DB update for marking the link as paid.
      // The Supabase builder is awaited as a thenable, so `then` must call its
      // `onFulfilled` argument directly (Promise/A+ spec).
      const mockChain = {
        update: jest.fn().mockReturnThis(),
        eq: jest.fn().mockReturnThis(),
        then: jest.fn().mockImplementation((resolve: (v: unknown) => void) =>
          resolve({ error: null }),
        ),
      };
      jest.spyOn(mockSupabase, 'getClient').mockReturnValue({
        from: jest.fn().mockReturnValue(mockChain),
      } as unknown as ReturnType<typeof mockSupabase.getClient>);

      const result = await service.processTransaction(tx, [link]);

      expect(result.decision).toBe(MatchDecision.AutoMatch);
      expect(result.bestLink?.id).toBe(link.id);
      expect(result.bestScore?.confidence).toBe(100);
    });

    it('queues for review when confidence is between thresholds', async () => {
      const tx = makeTx({ amount: '99.0000000' }); // amount mismatch → 60
      const link = makeLink();
      // Unique memo → 60 points, no amount → 60 total (≥ REVIEW_THRESHOLD=55)

      const result = await service.processTransaction(tx, [link]);

      expect(result.decision).toBe(MatchDecision.ReviewRequired);
      expect(mockUnmatchedQueue.enqueue).toHaveBeenCalledWith(
        tx,
        link.id,
        60,
      );
    });

    it('stores as unmatched when there are no candidates', async () => {
      const tx = makeTx({ memo: null, memoType: null, amount: '0.0100000' });
      const link = makeLink({ amount: '10.0000000' }); // large delta → 0 amount points

      const result = await service.processTransaction(tx, [link]);

      expect(result.decision).toBe(MatchDecision.Unmatched);
      expect(mockUnmatchedQueue.enqueue).toHaveBeenCalledWith(tx, null, null);
    });

    it('emits auto_reconciliation.succeeded event on auto-match', async () => {
      const tx = makeTx();
      const link = makeLink();

      const mockChain = {
        update: jest.fn().mockReturnThis(),
        eq: jest.fn().mockReturnThis(),
        then: jest.fn().mockImplementation((resolve: (v: unknown) => void) =>
          resolve({ error: null }),
        ),
      };
      jest.spyOn(mockSupabase, 'getClient').mockReturnValue({
        from: jest.fn().mockReturnValue(mockChain),
      } as unknown as ReturnType<typeof mockSupabase.getClient>);

      await service.processTransaction(tx, [link]);

      expect(mockEventEmitter.emit).toHaveBeenCalledWith(
        'auto_reconciliation.succeeded',
        expect.objectContaining({
          linkId: link.id,
          ownerPublicKey: link.owner_public_key,
          txHash: tx.txHash,
          confidence: 100,
        }),
      );
    });
  });

  // ─── runAutoMatchCycle ─────────────────────────────────────────────────────

  describe('runAutoMatchCycle()', () => {
    it('returns zero counts when there are no open payment links', async () => {
      jest.spyOn(mockSupabase, 'getClient').mockReturnValue({
        from: jest.fn().mockReturnValue({
          select: jest.fn().mockReturnThis(),
          eq: jest.fn().mockReturnThis(),
          or: jest.fn().mockResolvedValue({ data: [], error: null }),
        }),
      } as unknown as ReturnType<typeof mockSupabase.getClient>);

      const result = await service.runAutoMatchCycle();

      expect(result).toEqual({ processed: 0, matched: 0, queued: 0, unmatched: 0 });
    });

    it('skips when a cycle is already running', async () => {
      // Simulate a running cycle by setting the flag via handleCron guard
      (service as unknown as { isRunning: boolean }).isRunning = true;

      await service.handleCron();

      // No DB calls should have been made
      expect(mockSupabase.getClient).not.toHaveBeenCalled();

      (service as unknown as { isRunning: boolean }).isRunning = false;
    });
  });

  // ─── running getter ────────────────────────────────────────────────────────

  describe('running getter', () => {
    it('reflects the internal isRunning flag', () => {
      const s = service as unknown as { isRunning: boolean };
      expect(service.running).toBe(false);
      s.isRunning = true;
      expect(service.running).toBe(true);
      s.isRunning = false;
    });
  });
});
