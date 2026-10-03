import { Controller, Get, Query } from "@nestjs/common";
import { ApiOperation, ApiResponse, ApiTags } from "@nestjs/swagger";
import { RequiresIndexerLagCheck } from "../indexer-lag/requires-indexer-lag-check.decorator";

@ApiTags("Reconciliation")
@Controller("reconciliation")
export class ReconciliationController {
  @Get()
  @RequiresIndexerLagCheck()
  @ApiOperation({
    summary: "Get reconciliation reports",
    description: "Retrieves asset reconciliation records between database ledgers and Stellar state. Fails closed with 503 if indexer is lagging.",
  })
  @ApiResponse({ status: 200, description: "Reconciliation records retrieved." })
  @ApiResponse({ status: 503, description: "Indexer lagging." })
  async getReconciliation(@Query() query: any) {
    return { records: [] };
  }
}