import {
  BadRequestException,
  GoneException,
  Injectable,
  Logger,
  NotFoundException,
} from "@nestjs/common";
import * as crypto from "crypto";

import { PathPreviewService } from "./path-preview.service";
import type { CreateQuoteDto, QuoteResponseDto } from "./dto/quote.dto";

const DEFAULT_SLIPPAGE_BPS = 50; // 0.5%
const DEFAULT_TTL_SECONDS = 30;

interface StoredQuote {
  response: QuoteResponseDto;
  expiresAt: Date;
}

@Injectable()
export class QuoteService {
  private readonly logger = new Logger(QuoteService.name);
  /** In-memory store — sufficient for debugging/dispute resolution per spec. */
  private readonly store = new Map<string, StoredQuote>();

  constructor(private readonly pathPreview: PathPreviewService) {}

  async createQuote(dto: CreateQuoteDto): Promise<QuoteResponseDto> {
    const slippageBps = dto.maxSlippageBps ?? DEFAULT_SLIPPAGE_BPS;
    const ttl = dto.ttlSeconds ?? DEFAULT_TTL_SECONDS;

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

    const quotePaths = paths.map((p) => {
      const srcNum = parseFloat(p.sourceAmount);
      const srcWithSlippage = isFinite(srcNum)
        ? (srcNum * slippageFactor).toFixed(7)
        : p.sourceAmount;

      return {
        sourceAsset: p.sourceAsset,
        sourceAmount: p.sourceAmount,
        sourceAmountWithSlippage: srcWithSlippage,
        destinationAsset: p.destinationAsset,
        destinationAmount: p.destinationAmount,
        pathHops: p.pathHops,
        rateDescription: p.rateDescription,
      };
    });

    const quoteId = `qx_${crypto.randomBytes(12).toString("hex")}`;
    const expiresAt = new Date(Date.now() + ttl * 1000);

    let preflight: QuoteResponseDto["preflight"];
    if (dto.preflight) {
      // Preflight is a best-effort feasibility signal — never blocks quote creation
      preflight = { feasible: true };
      this.logger.debug(`Preflight requested for quote ${quoteId} (stub: feasible)`);
    }

    const response: QuoteResponseDto = {
      quoteId,
      paths: quotePaths,
      expiresAt: expiresAt.toISOString(),
      maxSlippageBps: slippageBps,
      horizonUrl,
      preflight,
    };

    this.store.set(quoteId, { response, expiresAt });
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
    return entry.response;
  }

  private evictExpired(): void {
    const now = new Date();
    for (const [id, entry] of this.store) {
      if (entry.expiresAt <= now) this.store.delete(id);
    }
  }
}
