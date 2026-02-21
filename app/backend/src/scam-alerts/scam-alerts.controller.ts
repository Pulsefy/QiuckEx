import { Controller, Post, Body, HttpCode, HttpStatus } from "@nestjs/common";
import { ApiTags, ApiOperation, ApiResponse, ApiBody } from "@nestjs/swagger";
import { ScamAlertsService } from "./scam-alerts.service";
import { ScanLinkDto } from "../dto";
import { ScanResultDto } from "./dto/scan-result.dto";

@ApiTags("scam-alerts")
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
  scan(@Body() scanLinkDto: ScanLinkDto): ScanResultDto {
    return this.scamAlertsService.scanLink(scanLinkDto);
  }
}
