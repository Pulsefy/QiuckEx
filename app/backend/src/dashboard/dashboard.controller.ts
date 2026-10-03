import { Controller, Get, Query, UseGuards } from "@nestjs/common";
import { ApiOperation, ApiResponse, ApiTags } from "@nestjs/swagger";
import { RequiresIndexerLagCheck } from "../indexer-lag/requires-indexer-lag-check.decorator";

@ApiTags("Dashboard")
@Controller("dashboard")
export class DashboardController {
  @Get("feed")
  @RequiresIndexerLagCheck()
  @ApiOperation({
    summary: "Get dashboard feed",
    description: "Retrieves aggregated user dashboard activity from indexed data. Fails closed with 503 if the indexer lags.",
  })
  @ApiResponse({ status: 200, description: "Dashboard feed retrieved." })
  @ApiResponse({ status: 503, description: "Indexer lagging." })
  async getDashboardFeed(@Query() query: any) {
    return { feed: [] };
  }
}