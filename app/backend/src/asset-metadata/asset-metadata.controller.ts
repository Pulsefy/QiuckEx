import {
  Controller,
  Get,
  Param,
  Post,
  HttpCode,
  HttpStatus,
  Logger,
  UseGuards,
} from "@nestjs/common";
import {
  ApiHeader,
  ApiOperation,
  ApiResponse,
  ApiTags,
  ApiParam,
} from "@nestjs/swagger";

import { ApiKeyGuard } from "../auth/guards/api-key.guard";
import { AssetMetadataService } from "./asset-metadata.service";
import {
  AssetMetadataResponseDto,
  AssetListResponseDto,
} from "./dto/asset-metadata.dto";

@ApiTags("assets")
@ApiHeader({
  name: "X-API-Key",
  description: "Optional API key for higher rate limits",
  required: false,
})
@UseGuards(ApiKeyGuard)
@Controller("assets")
export class AssetMetadataController {
  private readonly logger = new Logger(AssetMetadataController.name);

  constructor(private readonly assetMetadataService: AssetMetadataService) {}

  @Get()
  @ApiOperation({
    summary: "List all verified assets with metadata",
    description:
      "Returns all verified assets with their branding information, icons, and metadata from TOML files.",
  })
  @ApiResponse({
    status: 200,
    description: "List of assets with metadata",
    type: AssetListResponseDto,
  })
  async getAllAssets(): Promise<AssetListResponseDto> {
    this.logger.debug("Fetching all assets metadata");
    return this.assetMetadataService.getAllAssetsMetadata();
  }

  @Get(":code")
  @ApiOperation({
    summary: "Get metadata for a specific asset",
    description:
      "Returns detailed metadata including branding, icons, and TOML-parsed information for the specified asset code.",
  })
  @ApiParam({
    name: "code",
    description: "Asset code (e.g., USDC, XLM, AQUA)",
    example: "USDC",
  })
  @ApiResponse({
    status: 200,
    description: "Asset metadata retrieved successfully",
    type: AssetMetadataResponseDto,
  })
  @ApiResponse({
    status: 404,
    description: "Asset not found or not verified",
  })
  async getAssetMetadata(
    @Param("code") code: string,
  ): Promise<AssetMetadataResponseDto> {
    this.logger.debug(`Fetching metadata for asset: ${code}`);
    return this.assetMetadataService.getAssetMetadata(code);
  }

  @Post(":code/refresh")
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: "Refresh asset metadata cache",
    description:
      "Clears the cache for the specified asset and re-fetches metadata from TOML.",
  })
  @ApiParam({
    name: "code",
    description: "Asset code to refresh (e.g., USDC)",
    example: "USDC",
  })
  @ApiResponse({
    status: 200,
    description: "Asset metadata refreshed successfully",
    type: AssetMetadataResponseDto,
  })
  async refreshAssetMetadata(
    @Param("code") code: string,
  ): Promise<AssetMetadataResponseDto> {
    this.logger.log(`Refreshing metadata for asset: ${code}`);
    return this.assetMetadataService.refreshAssetMetadata(code);
  }

  @Get("cache/stats")
  @ApiOperation({
    summary: "Get cache statistics",
    description: "Returns statistics about the asset metadata cache.",
  })
  @ApiResponse({
    status: 200,
    description: "Cache statistics",
  })
  getCacheStats(): { size: number; maxSize: number; ttl: number } {
    return this.assetMetadataService.getCacheStats();
  }

  @Post("cache/clear")
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({
    summary: "Clear asset metadata cache",
    description: "Clears all cached asset metadata entries.",
  })
  @ApiResponse({
    status: 204,
    description: "Cache cleared successfully",
  })
  clearCache(): void {
    this.logger.log("Clearing asset metadata cache");
    this.assetMetadataService.clearCache();
  }
}
