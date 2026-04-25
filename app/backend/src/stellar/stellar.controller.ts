import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Post,
  ServiceUnavailableException,
  UseGuards,
  UsePipes,
  ValidationPipe,
} from "@nestjs/common";
import { ApiHeader, ApiOperation, ApiParam, ApiResponse, ApiTags } from "@nestjs/swagger";

import { ApiKeyGuard } from "../auth/guards/api-key.guard";
import { AssetMetadataService } from "../asset-metadata/asset-metadata.service";
import { AssetListResponseDto } from "../asset-metadata/dto/asset-metadata.dto";
import { AppConfigService } from "../config/app-config.service";
import { TransactionsService } from "../transactions/transaction.service";
import {
  PathPreviewRequestDto,
  StrictSendPathPreviewRequestDto,
} from "./dto/path-preview.dto";
import { CreateQuoteDto, QuoteResponseDto } from "./dto/quote.dto";
import { SorobanPreflightDto } from "./dto/soroban-preflight.dto";
import { PathPreviewService } from "./path-preview.service";
import { QuoteService } from "./quote.service";

@ApiTags("stellar")
@ApiHeader({
  name: "X-API-Key",
  description: "Optional API key for higher rate limits",
  required: false,
})
@UseGuards(ApiKeyGuard)
@Controller("stellar")
export class StellarController {
  constructor(
    private readonly pathPreviewService: PathPreviewService,
    private readonly transactionsService: TransactionsService,
    private readonly appConfig: AppConfigService,
    private readonly assetMetadataService: AssetMetadataService,
    private readonly quoteService: QuoteService,
  ) {}

  @Get("verified-assets")
  @ApiOperation({
    summary: "List verified assets for payment links and path swaps",
    description:
      "Returns all verified assets with branding metadata including logos and descriptions from TOML files.",
  })
  @ApiResponse({
    status: 200,
    description: "List of verified assets with metadata",
    type: AssetListResponseDto,
  })
  async getVerifiedAssets(): Promise<AssetListResponseDto> {
    return this.assetMetadataService.getAllAssetsMetadata();
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

  @Post("quote")
  @HttpCode(HttpStatus.OK)
  @UsePipes(new ValidationPipe({ transform: true, whitelist: true }))
  @ApiOperation({
    summary: "Create a path payment quote",
    description:
      "Computes path payment routes with slippage tolerance and a TTL. " +
      "Returns a quote ID that can be retrieved until expiry.",
  })
  @ApiResponse({ status: 200, description: "Quote created", type: QuoteResponseDto })
  @ApiResponse({ status: 400, description: "No path found or invalid parameters" })
  async createQuote(@Body() body: CreateQuoteDto): Promise<QuoteResponseDto> {
    return this.quoteService.createQuote(body);
  }

  @Get("quote/:quoteId")
  @ApiOperation({
    summary: "Retrieve a quote by ID",
    description: "Returns the stored quote. Returns 410 Gone if the quote has expired.",
  })
  @ApiParam({ name: "quoteId", description: "Quote ID returned by POST /stellar/quote" })
  @ApiResponse({ status: 200, description: "Quote details", type: QuoteResponseDto })
  @ApiResponse({ status: 404, description: "Quote not found" })
  @ApiResponse({ status: 410, description: "Quote expired" })
  getQuote(@Param("quoteId") quoteId: string): QuoteResponseDto {
    return this.quoteService.getQuote(quoteId);
  }
}
