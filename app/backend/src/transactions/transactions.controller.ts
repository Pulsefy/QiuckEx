import { Controller, Get, Query, UseGuards } from "@nestjs/common";
import { ApiOperation, ApiResponse, ApiTags } from "@nestjs/swagger";
import { RequiresIndexerLagCheck } from "../indexer-lag/requires-indexer-lag-check.decorator";
import { SorobanErrorCode } from "../common/soroban-errors";

@ApiTags("Transactions")
@Controller("transactions")
export class TransactionsController {
  @Get()
  @RequiresIndexerLagCheck()
  @ApiOperation({
    summary: "Get transactions",
    description: "Retrieves indexed transactions. Fails closed with 503 and Retry-After if the indexer is lagging behind the network threshold.",
  })
  @ApiResponse({ status: 200, description: "Transactions retrieved successfully." })
  @ApiResponse({
    status: 503,
    description: "Indexer is lagging behind the network. Operations temporarily disabled.",
    headers: {
      "Retry-After": {
        description: "Recommended retry delay in seconds",
        schema: { type: "integer" },
      },
    },
  })
  async getTransactions(@Query() query: any) {
    return { transactions: [] };
  }

  @Get("timeline")
  @RequiresIndexerLagCheck()
  @ApiOperation({
    summary: "Get transaction timeline",
    description: "Retrieves transaction timeline data from indexed storage. Fails closed with 503 if lagging.",
  })
  @ApiResponse({ status: 200, description: "Timeline retrieved successfully." })
  @ApiResponse({ status: 503, description: "Indexer is lagging." })
  async getTimeline(@Query() query: any) {
    return { timeline: [] };
  }
}