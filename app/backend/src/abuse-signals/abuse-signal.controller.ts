import {
  Controller,
  Get,
  Query,
  HttpCode,
  HttpStatus,
  ParseIntPipe,
  DefaultValuePipe,
} from "@nestjs/common";
import { ApiTags, ApiOperation, ApiQuery, ApiOkResponse } from "@nestjs/swagger";
import { AbuseSignalService } from "./abuse-signal.service";
import { RateLimitTier } from "../auth/decorators/rate-limit-group.decorator";
import {
  AbuseScoreSummaryDto,
  AbuseSignalAggregationDto,
  ListAbuseSignalsResponseDto,
  PruneAbuseSignalsResponseDto,
} from "./dto/abuse-signal-response.dto";

@ApiTags("admin/abuse-signals")
@Controller("admin/abuse-signals")
export class AbuseSignalController {
  constructor(private readonly abuseSignalService: AbuseSignalService) {}

  @Get("suspicious")
  @RateLimitTier("public-read")
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: "List suspicious abuse signals",
    description:
      "Returns signals with abuse score above the configured threshold. " +
      "Use this to identify scraping, brute-force, or replay activity on public payment pages.",
  })
  @ApiQuery({
    name: "minScore",
    description: "Minimum abuse score filter (0-100)",
    required: false,
    example: 20,
  })
  @ApiQuery({
    name: "limit",
    description: "Maximum results",
    required: false,
    example: 50,
  })
  @ApiOkResponse({
    description: "List of suspicious abuse signals",
    type: ListAbuseSignalsResponseDto,
  })
  async getSuspicious(
    @Query("minScore", new DefaultValuePipe(20), ParseIntPipe) minScore: number,
    @Query("limit", new DefaultValuePipe(50), ParseIntPipe) limit: number,
  ): Promise<ListAbuseSignalsResponseDto> {
    const signals = await this.abuseSignalService.getHighScoreSignals(
      minScore,
      Math.min(limit, 200),
    );
    return { signals, count: signals.length };
  }

  @Get("by-ip")
  @RateLimitTier("public-read")
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: "Get signals by IP address hash",
    description:
      "Look up all signals recorded for a specific IP address hash. " +
      "The hash is the SHA-256 of the raw IP + salt.",
  })
  @ApiQuery({
    name: "ipHash",
    description: "SHA-256 hash of the IP address",
    required: true,
    example: "a1b2c3d4e5f6...",
  })
  @ApiQuery({
    name: "limit",
    description: "Maximum results",
    required: false,
    example: 50,
  })
  @ApiOkResponse({
    description: "List of signals matching IP hash",
    type: ListAbuseSignalsResponseDto,
  })
  async getByIp(
    @Query("ipHash") ipHash: string,
    @Query("limit", new DefaultValuePipe(50), ParseIntPipe) limit: number,
  ): Promise<ListAbuseSignalsResponseDto> {
    if (!ipHash) {
      return { signals: [], count: 0 };
    }
    const signals = await this.abuseSignalService.getSignalsByIpHash(
      ipHash,
      Math.min(limit, 200),
    );
    return { signals, count: signals.length };
  }

  @Get("summary")
  @RateLimitTier("public-read")
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: "Abuse signal summary aggregation",
    description:
      "Aggregated view of abuse signals for the specified time window. " +
      "Provides total counts, top tags, top targets, and outcome breakdowns.",
  })
  @ApiQuery({
    name: "sinceMinutes",
    description: "Look-back window in minutes",
    required: false,
    example: 60,
  })
  @ApiOkResponse({
    description: "Aggregated abuse summary",
    type: AbuseSignalAggregationDto,
  })
  async getSummary(
    @Query("sinceMinutes", new DefaultValuePipe(60), ParseIntPipe)
    sinceMinutes: number,
  ): Promise<AbuseSignalAggregationDto> {
    return this.abuseSignalService.getAggregation(sinceMinutes);
  }

  @Get("ip-summaries")
  @RateLimitTier("public-read")
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: "Per-IP abuse score summaries",
    description:
      "Aggregated per-IP summaries showing average abuse scores, top tags, " +
      "and target usernames. Useful for identifying the worst offenders.",
  })
  @ApiQuery({
    name: "minScore",
    description: "Minimum average abuse score filter",
    required: false,
    example: 20,
  })
  @ApiQuery({
    name: "limit",
    description: "Maximum IPs to return",
    required: false,
    example: 20,
  })
  @ApiOkResponse({
    description: "List of per-IP abuse summaries",
    type: [AbuseScoreSummaryDto],
  })
  async getIpSummaries(
    @Query("minScore", new DefaultValuePipe(20), ParseIntPipe) minScore: number,
    @Query("limit", new DefaultValuePipe(20), ParseIntPipe) limit: number,
  ): Promise<AbuseScoreSummaryDto[]> {
    return this.abuseSignalService.getIpSummaries(
      minScore,
      Math.min(limit, 100),
    );
  }

  @Get("prune")
  @RateLimitTier("mutation")
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: "Prune expired abuse signals",
    description:
      "Manually trigger cleanup of signals past their retention_until date. " +
      "Cleanup also runs automatically via a scheduled task.",
  })
  @ApiOkResponse({
    description: "Pruning operation result count",
    type: PruneAbuseSignalsResponseDto,
  })
  async prune(): Promise<PruneAbuseSignalsResponseDto> {
    const count = await this.abuseSignalService.pruneExpiredSignals();
    return { pruned: count };
  }
}

