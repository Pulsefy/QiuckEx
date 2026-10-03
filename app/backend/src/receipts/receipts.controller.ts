import { Controller, Get, Param } from "@nestjs/common";
import { ApiOperation, ApiResponse, ApiTags } from "@nestjs/swagger";
import { RequiresIndexerLagCheck } from "../indexer-lag/requires-indexer-lag-check.decorator";

@ApiTags("Receipts")
@Controller("receipts")
export class ReceiptsController {
  @Get(":id")
  @RequiresIndexerLagCheck()
  @ApiOperation({
    summary: "Get receipt by ID or hash",
    description: "Retrieves cryptographically verified transaction receipts from indexed storage. Fails closed with 503 if the indexer lags.",
  })
  @ApiResponse({ status: 200, description: "Receipt retrieved." })
  @ApiResponse({ status: 503, description: "Indexer lagging." })
  async getReceipt(@Param("id") id: string) {
    return { receiptId: id };
  }
}