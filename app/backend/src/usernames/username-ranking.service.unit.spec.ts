import { Test } from '@nestjs/testing';
import { NotFoundException } from '@nestjs/common';
import { UsernameRankingService, RankingWeights, RankableCandidate } from './username-ranking.service';
import { FeatureFlagsService } from '../feature-flags/feature-flags.service';

const DEFAULT_WEIGHTS: RankingWeights = {
  similarity: 1,
  transactionVolume: 0.5,
  lastActiveAt: 1,
  isFeatured: 2,
};

function makeFlag(weights: Partial<RankingWeights> = {}) {
  return {
    key: 'username.ranking_weights',
    name: 'Username Search Ranking Weights',
    description: '',
    enabled: true,
    killSwitch: false,
    rolloutPercentage: 100,
    allowedUsers: [],
    environments: [],
    metadata: { ...DEFAULT_WEIGHTS, ...weights },
    updatedAt: new Date(0).toISOString(),
    updatedBy: 'bootstrap',
  };
}

describe('UsernameRankingService', () => {
  let service: UsernameRankingService;
  let featureFlags: jest.Mocked<Pick<FeatureFlagsService, 'getFlagOrThrow'>>;

  beforeEach(async () => {
    featureFlags = {
      getFlagOrThrow: jest.fn().mockResolvedValue(makeFlag()),
    };

    const module = await Test.createTestingModule({
      providers: [
        UsernameRankingService,
        {
          provide: FeatureFlagsService,
          useValue: featureFlags,
        },
      ],
    }).compile();

    service = module.get(UsernameRankingService);
  });

  afterEach(() => {
    jest.clearAllMocks();
    // Reset private cache between tests
    (service as unknown as { cacheExpiresAt: number }).cacheExpiresAt = 0;
    (service as unknown as { cachedWeights: null }).cachedWeights = null;
  });

  describe('getWeights', () => {
    it('returns default weights when flag has default metadata', async () => {
      const weights = await service.getWeights();
      expect(weights).toEqual(DEFAULT_WEIGHTS);
    });

    it('merges partial overrides with defaults', async () => {
      featureFlags.getFlagOrThrow.mockResolvedValue(makeFlag({ isFeatured: 5 }));
      const weights = await service.getWeights();
      expect(weights.isFeatured).toBe(5);
      expect(weights.similarity).toBe(DEFAULT_WEIGHTS.similarity);
    });

    it('falls back to defaults when flag is not found', async () => {
      featureFlags.getFlagOrThrow.mockRejectedValue(new NotFoundException('not found'));
      const weights = await service.getWeights();
      expect(weights).toEqual(DEFAULT_WEIGHTS);
    });

    it('caches the result within TTL', async () => {
      await service.getWeights();
      await service.getWeights();
      expect(featureFlags.getFlagOrThrow).toHaveBeenCalledTimes(1);
    });

    it('re-fetches after TTL expires', async () => {
      await service.getWeights();
      // Expire the cache
      (service as unknown as { cacheExpiresAt: number }).cacheExpiresAt = Date.now() - 1;
      await service.getWeights();
      expect(featureFlags.getFlagOrThrow).toHaveBeenCalledTimes(2);
    });

    it('ignores negative weight values and uses default instead', async () => {
      featureFlags.getFlagOrThrow.mockResolvedValue(makeFlag({ similarity: -5 }));
      const weights = await service.getWeights();
      expect(weights.similarity).toBe(DEFAULT_WEIGHTS.similarity);
    });
  });

  describe('rank', () => {
    const weights: RankingWeights = {
      similarity: 1,
      transactionVolume: 0,
      lastActiveAt: 0,
      isFeatured: 0,
    };

    it('returns empty array unchanged', () => {
      expect(service.rank([], weights)).toEqual([]);
    });

    it('sorts by similarity score when only similarity weight is non-zero', () => {
      const items: RankableCandidate[] = [
        { similarityScore: 0.3 },
        { similarityScore: 0.9 },
        { similarityScore: 0.6 },
      ];
      const ranked = service.rank(items, weights);
      expect((ranked[0] as RankableCandidate).similarityScore).toBe(0.9);
      expect((ranked[1] as RankableCandidate).similarityScore).toBe(0.6);
      expect((ranked[2] as RankableCandidate).similarityScore).toBe(0.3);
    });

    it('boosts featured items when isFeatured weight is high', () => {
      const featuredWeights: RankingWeights = {
        similarity: 0,
        transactionVolume: 0,
        lastActiveAt: 0,
        isFeatured: 1,
      };
      const items: RankableCandidate[] = [
        { isFeatured: false },
        { isFeatured: true },
        { isFeatured: false },
      ];
      const ranked = service.rank(items, featuredWeights);
      expect((ranked[0] as RankableCandidate).isFeatured).toBe(true);
    });

    it('handles missing optional fields gracefully', () => {
      const items: RankableCandidate[] = [
        {},
        { similarityScore: 0.5 },
      ];
      expect(() => service.rank(items, DEFAULT_WEIGHTS)).not.toThrow();
    });

    it('handles zero-sum weights without crashing (divides equally)', () => {
      const zeroWeights: RankingWeights = {
        similarity: 0,
        transactionVolume: 0,
        lastActiveAt: 0,
        isFeatured: 0,
      };
      const items: RankableCandidate[] = [{ similarityScore: 0.9 }, { similarityScore: 0.1 }];
      expect(() => service.rank(items, zeroWeights)).not.toThrow();
    });

    it('applies transaction-volume normalisation across the result set', () => {
      const volWeights: RankingWeights = {
        similarity: 0,
        transactionVolume: 1,
        lastActiveAt: 0,
        isFeatured: 0,
      };
      const items: RankableCandidate[] = [
        { transactionVolume: 100 },
        { transactionVolume: 10 },
        { transactionVolume: 50 },
      ];
      const ranked = service.rank(items, volWeights);
      expect((ranked[0] as RankableCandidate).transactionVolume).toBe(100);
      expect((ranked[2] as RankableCandidate).transactionVolume).toBe(10);
    });

    it('applies recency normalisation, preferring more recent lastActiveAt', () => {
      const recencyWeights: RankingWeights = {
        similarity: 0,
        transactionVolume: 0,
        lastActiveAt: 1,
        isFeatured: 0,
      };
      const old = '2020-01-01T00:00:00.000Z';
      const recent = '2025-01-01T00:00:00.000Z';
      const items: RankableCandidate[] = [
        { lastActiveAt: old },
        { lastActiveAt: recent },
      ];
      const ranked = service.rank(items, recencyWeights);
      expect((ranked[0] as RankableCandidate).lastActiveAt).toBe(recent);
    });
  });
});
