import { Controller, Get, Res, Headers } from "@nestjs/common";
import { ApiOperation, ApiTags, ApiResponse } from "@nestjs/swagger";
import { Response } from "express";
import { Throttle } from "@nestjs/throttler";
import { createHash } from "crypto";

import { HealthService } from "./health.service";
import { HealthResponseDto, ReadyResponseDto } from "./health-response.dto";
import { PublicStatusResponseDto } from "./public-status.dto";

@ApiTags("health")
@Controller()
export class HealthController {
  constructor(private readonly healthService: HealthService) {}

  @Get("health")
  @ApiOperation({
    summary: "Health check",
    description:
      "Returns application health status (shallow). Used for liveness probes.",
  })
  @ApiResponse({ status: 200, type: HealthResponseDto })
  async getHealth(@Res() res: Response) {
    const result = await this.healthService.getHealthStatus();
    return res.status(200).json(result);
  }

  @Get("ready")
  @ApiOperation({
    summary: "Readiness check",
    description:
      "Returns application readiness status including dependency checks (Supabase, environment). Used for readiness probes.",
  })
  @ApiResponse({ status: 200, type: ReadyResponseDto })
  @ApiResponse({
    status: 503,
    type: ReadyResponseDto,
    description: "Service not ready",
  })
  async getReadiness(@Res() res: Response) {
    const result = await this.healthService.getReadinessStatus();

    if (!result.ready) {
      return res.status(503).json(result);
    }

    return res.status(200).json(result);
  }

  @Get("status")
  @Throttle({ default: { limit: 5, ttl: 60000 } }) // 5 requests per minute for public status
  @ApiOperation({
    summary: "Public status page",
    description:
      "Returns a minimal, cacheable status suitable for a public status page. No sensitive details exposed.",
  })
  @ApiResponse({ status: 200, type: PublicStatusResponseDto })
  async getPublicStatus(
    @Res() res: Response,
    @Headers("if-none-match") ifNoneMatch?: string,
  ) {
    const result = await this.healthService.getPublicStatus();

    // Generate ETag based on response content
    const etag = createHash("md5")
      .update(JSON.stringify(result))
      .digest("hex")
      .substring(0, 16);

    // Check if client has cached version
    if (ifNoneMatch && ifNoneMatch.includes(etag)) {
      return res.status(304).send();
    }

    // Set caching headers
    res.set("Cache-Control", "public, max-age=30, s-maxage=60"); // Cache for 30s client-side, 60s CDN
    res.set("ETag", `"${etag}"`);

    return res.status(200).json(result);
  }
}
