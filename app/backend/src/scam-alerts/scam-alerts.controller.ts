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
import { RateLimitGroupTag } from "../auth/decorators/rate-limit-group.decorator";

@ApiTags("scam-alerts")
@ApiHeader({
  name: "X-API-Key",
  description: "Optional API key for higher rate limits",
  required: false,
})
@UseGuards(ApiKeyGuard)
@Controller("links")
export class ScamAlertsController {
  constructor(private readonly scamAlertsService: ScamAlertsService) {}

  @Post("scan")
  @RateLimitGroupTag("public_abuse")
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
    description: "Rate limit exceeded – retry after Retry-After seconds",
  })
  async scan(@Body() scanLinkDto: ScanLinkDto): Promise<ScanResultDto> {
    const result = await this.scamAlertsService.scanLink(scanLinkDto);
    return result as unknown as ScanResultDto;
  }
}
