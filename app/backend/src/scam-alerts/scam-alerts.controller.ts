import {
  Controller,
  Post,
  Body,
  HttpCode,
  HttpStatus,
  UseGuards,
} from "@nestjs/common";
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBody,
  ApiHeader,
} from "@nestjs/swagger";
import { ScamAlertsService } from "./scam-alerts.service";
import { ScanLinkDto } from "../dto";
import { ScanResultDto } from "./dto/scan-result.dto";
import { ApiKeyGuard } from "../auth/guards/api-key.guard";
import { CustomThrottlerGuard } from "../auth/guards/custom-throttler.guard";

@ApiTags("scam-alerts")
@ApiHeader({
  name: "X-API-Key",
  description: "Optional API key for higher rate limits (120 req/min vs 20 req/min)",
  required: false,
})
@UseGuards(ApiKeyGuard, CustomThrottlerGuard)
@Controller("links")
export class ScamAlertsController {
  constructor(private readonly scamAlertsService: ScamAlertsService) {}

  @Post("scan")
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: "Scan a payment link for scam indicators",
    description:
      "Analyzes a payment link using heuristic rules to detect potential scams",
  })
  @ApiBody({
    type: ScanLinkDto,
    description: "Payment link details to scan",
  })
  @ApiResponse({
    status: 200,
    description: "Scan completed successfully",
    type: ScanResultDto,
  })
  @ApiResponse({
    status: 400,
    description: "Invalid input data",
  })
  @ApiResponse({
    status: 429,
    description: "Rate limit exceeded – retry after 60 seconds",
  })
  scan(@Body() scanLinkDto: ScanLinkDto): ScanResultDto {
    return this.scamAlertsService.scanLink(scanLinkDto);
  }
}
