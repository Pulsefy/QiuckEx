import { Controller, Get, Res } from "@nestjs/common";
import { ApiOperation, ApiTags, ApiResponse } from "@nestjs/swagger";
import { Response } from "express";

import { HealthService } from "./health.service";
import { HealthResponseDto, ReadyResponseDto } from "./health-response.dto";

@ApiTags("health")
@Controller()
export class HealthController {
  constructor(private readonly healthService: HealthService) { }

  @Get("health")
  @ApiOperation({
    summary: "Health check",
    description: "Returns application health status (shallow). Used for liveness probes.",
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
  @ApiResponse({ status: 503, type: ReadyResponseDto, description: "Service not ready" })
  async getReadiness(@Res() res: Response) {
    const result = await this.healthService.getReadinessStatus();

    if (!result.ready) {
      return res.status(503).json(result);
    }

    return res.status(200).json(result);
  }
}
