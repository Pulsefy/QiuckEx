import {
  Controller,
  Get,
  UseGuards,
  InternalServerErrorException,
} from "@nestjs/common";
import { ApiOperation, ApiResponse, ApiTags } from "@nestjs/swagger";
import { MetricsService } from "./metrics.service";
import { MetricsGuard } from "./metrics.guard";

@ApiTags("metrics")
@Controller("metrics")
export class MetricsController {
  constructor(private metricsService: MetricsService) {}

  @Get()
  @UseGuards(MetricsGuard)
  @ApiOperation({
    summary: "Get Prometheus metrics",
    description:
      "Returns the current metrics in Prometheus format. Requires internal metrics guard.",
  })
  @ApiResponse({
    status: 200,
    description: "Prometheus metrics retrieved successfully",
    type: String,
  })
  @ApiResponse({
    status: 500,
    description: "Metrics registry not initialized or retrieval failed",
  })
  async getMetrics(): Promise<string> {
    try {
      const registry = this.metricsService.getRegistry();

      if (!registry) {
        throw new InternalServerErrorException(
          "Metrics registry not initialized",
        );
      }

      if (typeof registry.metrics !== "function") {
        throw new InternalServerErrorException("Metrics method not available");
      }

      return await registry.metrics();
    } catch (error) {
      if (error instanceof InternalServerErrorException) {
        throw error;
      }
      throw new InternalServerErrorException("Failed to retrieve metrics");
    }
  }

  @Get("content-type")
  @ApiOperation({
    summary: "Get metrics content type",
    description: "Returns the content type for the Prometheus metrics.",
  })
  @ApiResponse({
    status: 200,
    description: "Metrics content type retrieved successfully",
    schema: {
      type: "object",
      properties: {
        type: {
          type: "string",
          example: "text/plain; version=0.0.4; charset=utf-8",
        },
      },
    },
  })
  getContentType(): { type: string } {
    try {
      const registry = this.metricsService.getRegistry();

      if (!registry) {
        return { type: undefined };
      }

      return { type: registry.contentType };
    } catch (error) {
      throw error;
    }
  }
}
