import { Controller, Get, Res } from "@nestjs/common";
import { ApiOperation, ApiTags } from "@nestjs/swagger";
import { Response } from "express";

import { HealthService } from "./health.service";

@ApiTags("health")
@Controller("health")
export class HealthController {
  constructor(private readonly healthService: HealthService) {}

  @Get()
  @ApiOperation({
    summary: "Health check",
    description:
      "Returns application health status including dependency checks.",
  })
  async getHealth(@Res() res: Response) {
    const result = await this.healthService.getHealthStatus();

    if (result.status === "degraded") {
      return res.status(503).json(result);
    }

    return res.status(200).json(result);
  }
}
