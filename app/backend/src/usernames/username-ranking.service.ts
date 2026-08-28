/**
 * UsernameRankingService
 *
 * Loads configurable ranking weights from the `username.ranking_weights`
 * feature flag and applies them to a list of search results.
 *
 * ## Ranking formula
 *
 * Each candidate receives a composite score in the range [0, 1]:
 *
 * ```
 * score = w_similarity   * normalizedSimilarity
 *       + w_txVolume     * normalizedTxVolume
 *       + w_lastActiveAt * normalizedRecency
 *       + w_isFeatured   * (isFeatured ? 1 : 0)
 * ```
 *
 * Where every `w_*` weight is normalised so the four weights sum to 1 before
 * the formula is applied.  Normalisation means admins can supply raw weights
 * such as `{ similarity: 3, isFeatured: 1 }` without caring about total sums.
 *
 * Individual component normalisation:
 * - `normalizedSimilarity`   — the raw similarity score (already 0–1 from pg_trgm)
 * - `normalizedTxVolume`     — min-max scaled across the result set
 * - `normalizedRecency`      — inverse-age scaled (most recent = 1.0)
 * - `isFeatured`             — binary 1 / 0
 *
 * Weights are cached in memory for `RANKING_WEIGHTS_TTL_MS` (default 60 s) to
 * avoid a Supabase round-trip on every search request.
 */

import { Injectable, Logger } from '@nestjs/common';
import { FeatureFlagsService } from '../feature-flags/feature-flags.service';

/** Shape stored in the feature-flag metadata field. */
export interface RankingWeights {
  /** Weight for fuzzy similarity score (pg_trgm). */
  similarity: number;
  /** Weight for historical transaction volume. */
  transactionVolume: number;
  /** Weight for recency (last_active_at). */
  lastActiveAt: number;
  /** Weight for featured status boost. */
  isFeatured: number;
}

/** Candidate item that the ranking service can score. */
export interface RankableCandidate {
  /** Similarity score in [0, 1] from the database. */
  similarityScore?: number;
  /** Approximate transaction volume (raw count or amount). */
  transactionVolume?: number;
  /** ISO-8601 timestamp of last activity. */
  lastActiveAt?: string;
  /** Whether this profile is currently featured. */
  isFeatured?: boolean;
}

const FLAG_KEY = 'username.ranking_weights';

const DEFAULT_WEIGHTS: RankingWeights = {
  similarity: 1,
  transactionVolume: 0.5,
  lastActiveAt: 1,
  isFeatured: 2,
};

const RANKING_WEIGHTS_TTL_MS = 60_000; // 1 minute

@Injectable()
export class UsernameRankingService {
  private readonly logger = new Logger(UsernameRankingService.name);

  /** In-memory cache entry. */
  private cachedWeights: RankingWeights | null = null;
  private cacheExpiresAt = 0;

  constructor(private readonly featureFlagsService: FeatureFlagsService) {}

  /**
   * Return ranking weights, using the in-memory cache when fresh.
   */
  async getWeights(): Promise<RankingWeights> {
    if (this.cachedWeights && Date.now() < this.cacheExpiresAt) {
      return this.cachedWeights;
    }

    try {
      const flag = await this.featureFlagsService.getFlagOrThrow(FLAG_KEY);
      const meta = flag.metadata as Partial<RankingWeights> | undefined;
      const weights = this.parseWeights(meta);
      this.cachedWeights = weights;
      this.cacheExpiresAt = Date.now() + RANKING_WEIGHTS_TTL_MS;
      return weights;
    } catch {
      this.logger.warn(
        `Feature flag "${FLAG_KEY}" not found — using default ranking weights.`,
      );
      const weights = { ...DEFAULT_WEIGHTS };
      this.cachedWeights = weights;
      this.cacheExpiresAt = Date.now() + RANKING_WEIGHTS_TTL_MS;
      return weights;
    }
  }

  /**
   * Sort `items` by composite ranking score (descending).
   *
   * @param items    Array of candidates with ranking metadata.
   * @param weights  Pre-loaded weights (call `getWeights()` once per request).
   */
  rank<T extends RankableCandidate>(items: T[], weights: RankingWeights): T[] {
    if (items.length === 0) return items;

    const normalizedWeights = this.normalizeWeights(weights);

    // Pre-compute min/max of txVolume for normalisation.
    const volumes = items
      .map((i) => i.transactionVolume ?? 0)
      .filter((v) => v > 0);
    const maxVolume = volumes.length > 0 ? Math.max(...volumes) : 1;

    // Pre-compute min/max of lastActiveAt for normalisation.
    const timestamps = items
      .map((i) => (i.lastActiveAt ? new Date(i.lastActiveAt).getTime() : 0))
      .filter((t) => t > 0);
    const minTs = timestamps.length > 0 ? Math.min(...timestamps) : 0;
    const maxTs = timestamps.length > 0 ? Math.max(...timestamps) : Date.now();
    const tsRange = maxTs - minTs || 1;

    const scored = items.map((item) => {
      const s = item.similarityScore ?? 0;

      const vol = item.transactionVolume ?? 0;
      const normVol = maxVolume > 0 ? vol / maxVolume : 0;

      const ts = item.lastActiveAt
        ? new Date(item.lastActiveAt).getTime()
        : 0;
      const normTs = ts > 0 ? (ts - minTs) / tsRange : 0;

      const featured = item.isFeatured ? 1 : 0;

      const score =
        normalizedWeights.similarity * s +
        normalizedWeights.transactionVolume * normVol +
        normalizedWeights.lastActiveAt * normTs +
        normalizedWeights.isFeatured * featured;

      return { item, score };
    });

    scored.sort((a, b) => b.score - a.score);
    return scored.map((e) => e.item);
  }

  // ── Helpers ────────────────────────────────────────────────────────────────

  private parseWeights(meta?: Partial<RankingWeights>): RankingWeights {
    const merge = (key: keyof RankingWeights): number => {
      const raw = meta?.[key];
      if (typeof raw === 'number' && raw >= 0 && Number.isFinite(raw)) {
        return raw;
      }
      return DEFAULT_WEIGHTS[key];
    };

    return {
      similarity: merge('similarity'),
      transactionVolume: merge('transactionVolume'),
      lastActiveAt: merge('lastActiveAt'),
      isFeatured: merge('isFeatured'),
    };
  }

  /**
   * Scale weights so they sum to 1 to keep scores in [0, 1].
   */
  private normalizeWeights(w: RankingWeights): RankingWeights {
    const sum =
      w.similarity + w.transactionVolume + w.lastActiveAt + w.isFeatured;
    if (sum === 0) return { similarity: 0.25, transactionVolume: 0.25, lastActiveAt: 0.25, isFeatured: 0.25 };
    return {
      similarity: w.similarity / sum,
      transactionVolume: w.transactionVolume / sum,
      lastActiveAt: w.lastActiveAt / sum,
      isFeatured: w.isFeatured / sum,
    };
  }
}
