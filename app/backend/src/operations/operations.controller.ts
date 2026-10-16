import { Controller, Get, Query, UseGuards } from "@nestjs/common";
import { ApiOperation, ApiResponse, ApiTags } from "@nestjs/swagger";

import { ApiKeyGuard } from "../auth/guards/api-key.guard";
import { RequireScopes } from "../auth/decorators/require-scopes.decorator";
import { OperationsService } from "./operations.service";
import { RateLimitTier } from "../auth/decorators/rate-limit-group.decorator";
import {
  IndexerStatusResponseDto,
  IngestionStatusResponseDto,
  WebhookBacklogResponseDto,
  RecentErrorsResponseDto,
} from "./dto/operations-response.dto";

@ApiTags("admin/operations")
@Controller("admin/operations")
@UseGuards(ApiKeyGuard)
export class OperationsController {
  constructor(
    private readonly operationsService: OperationsService,
  ) {}

  @Get("indexer")
  @RateLimitTier("public-read")
  @RequireScopes("admin")
  @ApiOperation({ summary: "Get indexer status and lag" })
  @ApiResponse({ status: 200, type: IndexerStatusResponseDto })
  async getIndexerStatus() {
    return this.operationsService.getIndexerStatus();
  }

  @Get("ingestion")
  @RateLimitTier("public-read")
  @RequireScopes("admin")
  @ApiOperation({ summary: "Get ingestion lag metrics" })
  @ApiResponse({ status: 200, type: IngestionStatusResponseDto })
  async getIngestionStatus() {
    return this.operationsService.getIngestionStatus();
  }

  @Get("webhooks")
  @RateLimitTier("public-read")
  @RequireScopes("admin")
  @ApiOperation({ summary: "Get webhook delivery backlog and retry count" })
  @ApiResponse({ status: 200, type: WebhookBacklogResponseDto })
  async getWebhookBacklog() {
    return this.operationsService.getWebhookBacklog();
  }

  @Get("errors")
  @RateLimitTier("public-read")
  @RequireScopes("admin")
  @ApiOperation({ summary: "Get recent system and audit errors" })
  @ApiResponse({ status: 200, type: RecentErrorsResponseDto })
  async getRecentErrors(
    @Query("page") page?: string,
    @Query("limit") limit?: string,
  ) {
    return this.operationsService.getRecentErrors(
      Number(page ?? 1),
      Number(limit ?? 50),
    );
  }
}