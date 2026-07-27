import { Controller, Get, Logger } from "@nestjs/common";
import { ApiTags, ApiOperation, ApiResponse } from "@nestjs/swagger";
import {
  EnvironmentParityService,
  ParityCheckResult,
} from "./environment-parity.service";

interface ParityStatusResponse {
  success: boolean;
  data: {
    checks: ParityCheckResult[];
    summary: {
      total: number;
      passed: number;
      failed: number;
      warnings: number;
    };
  };
}

interface HealthResponse {
  success: boolean;
  data: {
    healthy: boolean;
    failedChecks: number;
    totalChecks: number;
  };
}

@ApiTags("Environment Parity")
@Controller("api/environment-parity")
export class EnvironmentParityController {
  private readonly logger = new Logger(EnvironmentParityController.name);

  constructor(private readonly parityService: EnvironmentParityService) {}

  @Get("status")
  @ApiOperation({ summary: "Get environment parity check status" })
  @ApiResponse({ status: 200, description: "Returns parity check results" })
  getParityStatus(): ParityStatusResponse {
    const results = this.parityService.getResults();

    return {
      success: true,
      data: {
        checks: results,
        summary: {
          total: results.length,
          passed: results.filter((r) => r.status === "pass").length,
          failed: results.filter((r) => r.status === "fail").length,
          warnings: results.filter((r) => r.status === "warning").length,
        },
      },
    };
  }

  @Get("health")
  @ApiOperation({ summary: "Quick health check for environment parity" })
  @ApiResponse({ status: 200, description: "Returns health status" })
  getHealth(): HealthResponse {
    const results = this.parityService.getResults();
    const failed = results.filter((r) => r.status === "fail").length;

    return {
      success: true,
      data: {
        healthy: failed === 0,
        failedChecks: failed,
        totalChecks: results.length,
      },
    };
  }
}
