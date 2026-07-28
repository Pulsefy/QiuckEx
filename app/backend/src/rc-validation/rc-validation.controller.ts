import { Controller, Get, UseGuards } from "@nestjs/common";
import { ApiOperation, ApiResponse, ApiTags } from "@nestjs/swagger";

import { ApiKeyGuard } from "../auth/guards/api-key.guard";
import { RequireScopes } from "../auth/decorators/require-scopes.decorator";
import { RcValidationService } from "./rc-validation.service";
import { RcValidationReportDto } from "./dto/rc-report.dto";

@ApiTags("Release Candidate Validation")
@Controller("admin/rc-validation")
@UseGuards(ApiKeyGuard)
export class RcValidationController {
  constructor(private readonly rcValidationService: RcValidationService) {}

  @Get("report")
  @RequireScopes("admin")
  @ApiOperation({
    summary: "Generate a release-candidate validation report",
    description:
      "Aggregates smoke results, contract registry status, indexer lag metrics, " +
      "and environment parity into a single operator-friendly report with " +
      "classified, timestamped blockers so testnet release readiness can be " +
      "assessed from one endpoint.",
  })
  @ApiResponse({ status: 200, type: RcValidationReportDto })
  async getReport(): Promise<RcValidationReportDto> {
    return this.rcValidationService.generateReport();
  }
}
