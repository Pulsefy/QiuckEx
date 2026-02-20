import { Controller, Get, Query, UseGuards } from "@nestjs/common";
import { ApiOperation, ApiResponse, ApiTags, ApiHeader } from "@nestjs/swagger";

import {
  GetTransactionsQueryDto,
  TransactionResponseDto,
} from "./dto/transaction.dto";
import { HorizonService } from "./horizon.service";

import { ApiKeyGuard } from "../auth/guards/api-key.guard";
import { CustomThrottlerGuard } from "../auth/guards/custom-throttler.guard";

@ApiTags("transactions")
@ApiHeader({
  name: "X-API-Key",
  description: "Optional API key for higher rate limits",
  required: false,
})
@UseGuards(ApiKeyGuard, CustomThrottlerGuard)
@Controller("transactions")
export class TransactionsController {
  constructor(private readonly horizonService: HorizonService) {}

  @Get()
  @ApiOperation({
    summary: "Fetch recent Stellar transactions (payments)",
    description:
      "Fetches recent payment operations for a given account. " +
      "Results are cached for 60 seconds and support pagination via cursor. " +
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
    description: "Horizon service rate limit exceeded or unavailable",
  })
  async getTransactions(
    @Query() query: GetTransactionsQueryDto,
  ): Promise<TransactionResponseDto> {
    const { accountId, asset, limit, cursor } = query;

    return this.horizonService.getPayments(accountId, asset, limit, cursor);
  }
}
