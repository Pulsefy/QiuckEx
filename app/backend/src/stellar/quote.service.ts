import {
  BadRequestException,
  GoneException,
  Injectable,
  Logger,
  NotFoundException,
} from "@nestjs/common";
import * as crypto from "crypto";

import { PathPreviewService } from "./path-preview.service";
import type { CreateQuoteDto, QuoteResponseDto, QuotePathDto } from "./dto/quote.dto";

const DEFAULT_SLIPPAGE_BPS = 50; // 0.5%
const DEFAULT_TTL_SECONDS = 30;
const CACHE_TTL_MS = 10_000; // 10 seconds

interface StoredQuote {
  response: QuoteResponseDto;
  expiresAt: Date;
  fetchedAt: number;
  cacheSource: "hit" | "miss";
}

interface CacheEntry {
  paths: QuotePathDto[];
  horizonUrl: string;
  fetchedAt: number;
}

@Injectable()
export class QuoteService {
  private readonly logger = new Logger(QuoteService.name);
  /** In-memory store — sufficient for debugging/dispute resolution per spec. */
  private readonly store = new Map<string, StoredQuote>();
  /** Cache for Horizon/Soroban path preview results. */
  private readonly cache = new Map<string, CacheEntry>();

  constructor(private readonly pathPreview: PathPreviewService) {}

  private getCacheKey(dto: CreateQuoteDto): string {
    const dest = dto.destinationAsset.issuer
      ? `${dto.destinationAsset.code}:${dto.destinationAsset.issuer}`
      : dto.destinationAsset.code;
    const sources = dto.sourceAssets
      .map((a) => (a.issuer ? `${a.code}:${a.issuer}` : a.code))
      .join(",");
    const slippage = dto.maxSlippageBps ?? DEFAULT_SLIPPAGE_BPS;
    return `${dest}|${dto.destinationAmount}|${sources}|${slippage}`;
  }

  async createQuote(dto: CreateQuoteDto): Promise<QuoteResponseDto> {
    const slippageBps = dto.maxSlippageBps ?? DEFAULT_SLIPPAGE_BPS;
    const ttl = dto.ttlSeconds ?? DEFAULT_TTL_SECONDS;

    const cacheKey = this.getCacheKey(dto);
    const now = Date.now();
    const cached = this.cache.get(cacheKey);

    let useCache = false;
    let quotePaths: QuotePathDto[] = [];
    let horizonUrlStr = "";
    let fetchedAt = now;
    let cacheSource: "hit" | "miss" = "miss";

    if (cached && !dto.revalidate) {
      const isExpired = now - cached.fetchedAt > CACHE_TTL_MS;
      if (!isExpired) {
        useCache = true;
        quotePaths = cached.paths;
        horizonUrlStr = cached.horizonUrl;
        fetchedAt = cached.fetchedAt;
        cacheSource = "hit";
        this.logger.debug(`Cache hit for key: ${cacheKey}`);
      }
    }

    if (!useCache) {
      const { paths, horizonUrl } = await this.pathPreview.previewPaths({
        destinationAmount: dto.destinationAmount,
        destinationAsset: dto.destinationAsset,
        sourceAssets: dto.sourceAssets,
      });

      if (paths.length === 0) {
        throw new BadRequestException({
          code: "NO_PATH_FOUND",
          message: "No payment path found for the requested asset pair.",
        });
      }

      const slippageFactor = 1 + slippageBps / 10_000;

      quotePaths = paths.map((p) => {
        const srcNum = parseFloat(p.sourceAmount);
        const srcWithSlippage = isFinite(srcNum)
          ? (srcNum * slippageFactor).toFixed(7)
          : p.sourceAmount;

        const destNum = parseFloat(p.destinationAmount);
        const platformFee = isFinite(destNum) ? (destNum * 0.01).toFixed(7) : "0.0000000";
        const networkFee = "0.0000100"; // 100 stroops
        // Combining fees of potentially different assets into a single string is non-trivial without an oracle, 
        // but for API consistency we return the platform fee as the total fee (assuming the user pays network fee separately in XLM).
        const totalFee = platformFee;

        return {
          sourceAsset: p.sourceAsset,
          sourceAmount: p.sourceAmount,
          sourceAmountWithSlippage: srcWithSlippage,
          destinationAsset: p.destinationAsset,
          destinationAmount: p.destinationAmount,
          pathHops: p.pathHops,
          rateDescription: p.rateDescription,
          feeBreakdown: {
            networkFee,
            platformFee,
            totalFee,
          },
        };
      });

      horizonUrlStr = horizonUrl;
      fetchedAt = now;
      cacheSource = "miss";

      this.cache.set(cacheKey, {
        paths: quotePaths,
        horizonUrl,
        fetchedAt,
      });
      this.logger.debug(`Cache miss/refresh for key: ${cacheKey}`);
    }

    const quoteId = `qx_${crypto.randomBytes(12).toString("hex")}`;
    const expiresAt = new Date(now + ttl * 1000);

    let preflight: QuoteResponseDto["preflight"];
    if (dto.preflight) {
      // Preflight is a best-effort feasibility signal — never blocks quote creation
      preflight = { feasible: true };
      this.logger.debug(`Preflight requested for quote ${quoteId} (stub: feasible)`);
    }

    const age = Math.max(0, Math.floor((now - fetchedAt) / 1000));

    const response: QuoteResponseDto = {
      quoteId,
      paths: quotePaths,
      expiresAt: expiresAt.toISOString(),
      maxSlippageBps: slippageBps,
      horizonUrl: horizonUrlStr,
      preflight,
      age,
      cacheSource,
    };

    this.store.set(quoteId, { response, expiresAt, fetchedAt, cacheSource });
    this.logger.log(`Quote created: ${quoteId} expires ${expiresAt.toISOString()}`);

    // Evict expired entries lazily to avoid unbounded growth
    this.evictExpired();

    return response;
  }

  getQuote(quoteId: string): QuoteResponseDto {
    const entry = this.store.get(quoteId);
    if (!entry) {
      throw new NotFoundException({ code: "QUOTE_NOT_FOUND", message: "Quote not found." });
    }
    if (entry.expiresAt <= new Date()) {
      this.store.delete(quoteId);
      throw new GoneException({ code: "QUOTE_EXPIRED", message: "Quote has expired." });
    }
    const age = Math.max(0, Math.floor((Date.now() - entry.fetchedAt) / 1000));
    return {
      ...entry.response,
      age,
    };
  }

  private evictExpired(): void {
    const now = Date.now();
    for (const [id, entry] of this.store) {
      if (entry.expiresAt.getTime() <= now) this.store.delete(id);
    }
    for (const [key, entry] of this.cache) {
      if (entry.fetchedAt + CACHE_TTL_MS <= now) this.cache.delete(key);
    }
  }
}
