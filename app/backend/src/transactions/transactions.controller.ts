import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Query,
  UseGuards,
  UsePipes,
  ValidationPipe,
} from "@nestjs/common";
import { ApiOperation, ApiResponse, ApiTags, ApiHeader } from "@nestjs/swagger";

import {
  GetTransactionsQueryDto,
  TransactionResponseDto,
} from "./dto/transaction.dto";
import { HorizonService } from "./horizon.service";

import { ApiKeyGuard } from "../auth/guards/api-key.guard";
import { ComposeTransactionDto } from "./dto/compose-transaction.dto";
import { TransactionsService } from "./transaction.service";

@ApiTags("transactions")
@ApiHeader({
  name: "X-API-Key",
  description: "Optional API key for higher rate limits",
  required: false,
})
@UseGuards(ApiKeyGuard)
@Controller("transactions")
export class TransactionsController {
  constructor(
    private readonly horizonService: HorizonService,
    private readonly transactionService: TransactionsService,
  ) {}

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
  @UsePipes(new ValidationPipe({ transform: true, whitelist: true }))
  async compose(@Body() dto: ComposeTransactionDto) {
    return this.transactionService.composeTransaction(dto);
  }
}
