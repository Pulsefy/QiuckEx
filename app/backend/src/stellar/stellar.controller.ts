import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  ServiceUnavailableException,
  UseGuards,
  UsePipes,
  ValidationPipe,
} from "@nestjs/common";
import {
  ApiHeader,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from "@nestjs/swagger";

import { ApiKeyGuard } from "../auth/guards/api-key.guard";
import { CustomThrottlerGuard } from "../auth/guards/custom-throttler.guard";
import { AppConfigService } from "../config/app-config.service";
import { TransactionsService } from "../transactions/transaction.service";
import {
  PathPreviewRequestDto,
  StrictSendPathPreviewRequestDto,
} from "./dto/path-preview.dto";
import { SorobanPreflightDto } from "./dto/soroban-preflight.dto";
import { PathPreviewService } from "./path-preview.service";
import { VERIFIED_STELLAR_ASSETS } from "./verified-assets.constant";

@ApiTags("stellar")
@ApiHeader({
  name: "X-API-Key",
  description: "Optional API key for higher rate limits",
  required: false,
})
@UseGuards(ApiKeyGuard, CustomThrottlerGuard)
@Controller("stellar")
export class StellarController {
  constructor(
    private readonly pathPreviewService: PathPreviewService,
    private readonly transactionsService: TransactionsService,
    private readonly appConfig: AppConfigService,
  ) {}

  @Get("verified-assets")
  @ApiOperation({
    summary: "List verified assets for payment links and path swaps",
  })
  @ApiResponse({ status: 200 })
  getVerifiedAssets() {
    return { assets: [...VERIFIED_STELLAR_ASSETS] };
  }

  @Post("path-preview")
  @HttpCode(HttpStatus.OK)
  @UsePipes(new ValidationPipe({ transform: true, whitelist: true }))
  @ApiOperation({
    summary: "Strict-receive path preview (Horizon)",
    description:
      "Returns candidate paths and estimated source amounts for a fixed destination amount.",
  })
  async pathPreview(@Body() body: PathPreviewRequestDto) {
    return this.pathPreviewService.previewPaths(body);
  }

  @Post("path-preview/strict-send")
  @HttpCode(HttpStatus.OK)
  @UsePipes(new ValidationPipe({ transform: true, whitelist: true }))
  @ApiOperation({
    summary: "Strict-send path preview (Horizon)",
    description:
      "Returns candidate paths and estimated destination amounts for a fixed source amount.",
  })
  async strictSendPathPreview(@Body() body: StrictSendPathPreviewRequestDto) {
    return this.pathPreviewService.strictSendPaths(body);
  }

  @Post("soroban-preflight")
  @HttpCode(HttpStatus.OK)
  @UsePipes(new ValidationPipe({ transform: true, whitelist: true }))
  @ApiOperation({
    summary: "Run Soroban tx composer preflight (health_check simulation)",
    description:
      "Uses the same pipeline as POST /transactions/compose against QUICKEX_CONTRACT_ID.",
  })
  async sorobanPreflight(@Body() body: SorobanPreflightDto) {
    const contractId = this.appConfig.quickexContractId;
    if (!contractId?.trim()) {
      throw new ServiceUnavailableException({
        code: "CONTRACT_NOT_CONFIGURED",
        message:
          "Set QUICKEX_CONTRACT_ID to enable Soroban preflight simulation.",
      });
    }

    return this.transactionsService.composeTransaction({
      contractId: contractId.trim(),
      method: "health_check",
      params: [],
      sourceAccount: body.sourceAccount,
    });
  }
}
