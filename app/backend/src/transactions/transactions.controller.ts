import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Logger,
  Post,
  Query,
  Req,
  Res,
  UseGuards,
  UsePipes,
  ValidationPipe,
} from "@nestjs/common";
import { ApiOperation, ApiResponse, ApiTags, ApiHeader } from "@nestjs/swagger";
import type { Request, Response } from "express";

import {
  GetTransactionsQueryDto,
  TransactionResponseDto,
} from "./dto/transaction.dto";
import { HorizonService } from "./horizon.service";

import { ApiKeyGuard } from "../auth/guards/api-key.guard";
import { TESTNET_CONTRACT_WRITES_FLAG } from "../feature-flags/contract-write-kill-switch.constants";
import { NetworkSafetyGuard } from "../feature-flags/network-safety.guard";
import { RequiresFlag } from "../feature-flags/requires-flag.decorator";
import { ComposeTransactionDto, SimulateOperationDto, SubmitSignedTransactionDto } from "./dto/compose-transaction.dto";
import { TransactionsService } from "./transaction.service";
import { ContractMethodAllowlistGuard } from "../contracts/contract-method-allowlist.guard";
import { EtagCacheService, EtagCacheRoute } from "./etag-cache.service";

function correlationIdOf(req: Request): string | undefined {
  return (req as unknown as Record<string, unknown>)["correlationId"] as
    | string
    | undefined;
}

@ApiTags("transactions")
@ApiHeader({
  name: "X-API-Key",
  description: "Optional API key for higher rate limits",
  required: false,
})
@UseGuards(ApiKeyGuard)
@Controller("transactions")
export class TransactionsController {
  private readonly logger = new Logger(TransactionsController.name);

  constructor(
    private readonly horizonService: HorizonService,
    private readonly transactionService: TransactionsService,
    private readonly etagCache: EtagCacheService,
  ) {}

  private hasApiKey(req: Request): boolean {
    const value = req.headers["x-api-key"];
    return typeof value === "string" && value.length > 0;
  }

  /**
   * ETag-based caching for the expensive compose/simulate operations.
   * The cache key is the SHA-256 of the serialized request body. When the
   * client sends an If-None-Match header matching the computed ETag we return
   * 304 Not Modified. Requests carrying an X-API-Key header bypass the cache.
   */
  private async respondWithEtagCache(
    route: EtagCacheRoute,
    payload: unknown,
    req: Request,
    res: Response,
    compute: () => Promise<object>,
  ): Promise<unknown> {
    if (this.hasApiKey(req)) {
      const result = await compute();
      return { ...result, correlationId: correlationIdOf(req) };
    }

    const etag = this.etagCache.computeCacheKey(payload);
    res.setHeader("ETag", `"${etag}"`);
    res.setHeader("Cache-Control", "no-cache");

    const clientEtag = req.headers["if-none-match"];
    const cached = this.etagCache.get(route, etag);

    if (clientEtag && (clientEtag === `"${etag}"` || clientEtag === "*")) {
      if (cached !== undefined) {
        res.status(HttpStatus.NOT_MODIFIED);
        return;
      }
      this.logger.warn(`Conditional ETag miss [${route}]: ${etag}`);
    }

    if (cached !== undefined) {
      return { ...(cached as object), correlationId: correlationIdOf(req) };
    }

    const result = await compute();
    this.etagCache.set(route, etag, result);
    return { ...result, correlationId: correlationIdOf(req) };
  }

  @Get()
  @ApiOperation({
    summary: "Fetch recent Stellar transactions (payments)",
    description:
      "Fetches recent payment operations for a given account with caching and resilience. " +
      "Results are cached with configurable TTL (default 60 seconds) and support pagination via cursor. " +
      "Implements exponential backoff for Horizon API resilience and graceful degradation on failures. " +
      "This endpoint is rate-limited; API keys receive higher limits.",
  })
  @ApiResponse({
    status: 200,
    description: "List of normalized payment items",
    type: TransactionResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: "Invalid query parameters",
  })
  @ApiResponse({
    status: 429,
    description: "Rate limit exceeded",
  })
  @ApiResponse({
    status: 503,
    description:
      "Horizon service rate limit exceeded, unavailable, or backoff in effect",
  })
  @ApiResponse({
    status: 502,
    description: "Bad gateway when Horizon returns server errors",
  })
  async getTransactions(
    @Query() query: GetTransactionsQueryDto,
  ): Promise<TransactionResponseDto> {
    const { accountId, asset, limit, cursor } = query;

    return this.horizonService.getPayments(accountId, asset, limit, cursor);
  }
  @Post("compose")
  @HttpCode(HttpStatus.OK)
  @UseGuards(NetworkSafetyGuard, ContractMethodAllowlistGuard)
  @RequiresFlag(TESTNET_CONTRACT_WRITES_FLAG)
  @UsePipes(new ValidationPipe({ transform: true, whitelist: true }))
  @ApiOperation({
    summary: "Compose an unsigned Soroban transaction with ETag-based caching",
  })
  async compose(
    @Body() dto: ComposeTransactionDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    return this.respondWithEtagCache("compose", dto, req, res, () =>
      this.transactionService.composeTransaction(dto),
    );
  }

  @Post("build")
  @HttpCode(HttpStatus.OK)
  @UseGuards(NetworkSafetyGuard, ContractMethodAllowlistGuard)
  @RequiresFlag(TESTNET_CONTRACT_WRITES_FLAG)
  @UsePipes(new ValidationPipe({ transform: true, whitelist: true }))
  @ApiOperation({
    summary: "Build unsigned Soroban transaction XDR with canonical memo/params",
  })
  async buildUnsignedXdr(@Body() dto: ComposeTransactionDto, @Req() req: Request) {
    const result = await this.transactionService.composeTransaction(dto);
    return { ...result, correlationId: correlationIdOf(req) };
  }

  @Post("simulate")
  @HttpCode(HttpStatus.OK)
  @UseGuards(NetworkSafetyGuard, ContractMethodAllowlistGuard)
  @RequiresFlag(TESTNET_CONTRACT_WRITES_FLAG)
  @UsePipes(new ValidationPipe({ transform: true, whitelist: true }))
  @ApiOperation({
    summary: "Simulate contract operations with deterministic failure reasons",
  })
  async simulateOperation(
    @Body() dto: SimulateOperationDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    return this.respondWithEtagCache("simulate", dto, req, res, () =>
      this.transactionService.simulateOperation(dto),
    );
  }

  @Post("submit")
  @HttpCode(HttpStatus.OK)
  @UseGuards(NetworkSafetyGuard)
  @RequiresFlag(TESTNET_CONTRACT_WRITES_FLAG)
  @UsePipes(new ValidationPipe({ transform: true, whitelist: true }))
  @ApiOperation({
    summary: "Submit an already-signed transaction with idempotency support",
  })
  async submitSignedTransaction(
    @Body() dto: SubmitSignedTransactionDto,
    @Req() req: Request,
  ) {
    const result = await this.transactionService.submitSignedTransaction(dto);
    return { ...result, correlationId: correlationIdOf(req) };
  }
}
