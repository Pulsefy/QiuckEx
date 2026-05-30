import {
  Controller,
  Get,
  Param,
  Post,
  HttpCode,
  HttpStatus,
  Logger,
  UseGuards,
  Query,
  Req,
  Res,
  Body,
} from "@nestjs/common";
import {
  ApiHeader,
  ApiOperation,
  ApiResponse,
  ApiTags,
  ApiParam,
  ApiQuery,
} from "@nestjs/swagger";
import { Request, Response } from "express";
import * as crypto from "crypto";

import { ApiKeyGuard } from "../auth/guards/api-key.guard";
import { AssetMetadataService } from "./asset-metadata.service";
import {
  AssetMetadataResponseDto,
  AssetListResponseDto,
} from "./dto/asset-metadata.dto";
import { AdminVerifyAssetDto } from "./dto/admin-asset.dto";

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
      "Returns all verified assets with their branding information, icons, and metadata from TOML files. Supports searching by code or issuer.",
  })
  @ApiQuery({
    name: "q",
    description: "Search query to filter assets by code or issuer key",
    required: false,
    example: "USDC",
  })
  @ApiResponse({
    status: 200,
    description: "List of assets with metadata",
    type: AssetListResponseDto,
  })
  async getAllAssets(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
    @Query("q") query?: string,
  ): Promise<AssetListResponseDto | void> {
    this.logger.debug(`Fetching all assets metadata, search query: ${query || "none"}`);
    const data = await this.assetMetadataService.getAllAssetsMetadata(query);

    // Compute and set ETag header for caching
    const etag = `W/"${crypto
      .createHash("sha256")
      .update(JSON.stringify(data))
      .digest("hex")}"`;
    res.setHeader("ETag", etag);
    res.setHeader("Cache-Control", "public, max-age=0, must-revalidate");

    // Check If-None-Match conditional request
    if (req.headers["if-none-match"] === etag) {
      res.status(HttpStatus.NOT_MODIFIED);
      return;
    }

    return data;
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
  @ApiQuery({
    name: "issuer",
    description: "Asset issuer public key (null/omitted for native XLM)",
    required: false,
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
    @Query("issuer") issuer: string | undefined,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<AssetMetadataResponseDto | void> {
    this.logger.debug(`Fetching metadata for asset: ${code} (issuer: ${issuer || "none"})`);
    const data = await this.assetMetadataService.getAssetMetadata(code, issuer);

    // Compute and set ETag header for caching
    const etag = `W/"${crypto
      .createHash("sha256")
      .update(JSON.stringify(data))
      .digest("hex")}"`;
    res.setHeader("ETag", etag);
    res.setHeader("Cache-Control", "public, max-age=0, must-revalidate");

    // Check If-None-Match conditional request
    if (req.headers["if-none-match"] === etag) {
      res.status(HttpStatus.NOT_MODIFIED);
      return;
    }

    return data;
  }

  @Post("admin/verify")
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: "Mark asset verified or unverified",
    description:
      "Admin workflow to verify/unverify assets and store them in the database.",
  })
  @ApiResponse({
    status: 200,
    description: "Asset verification status updated successfully",
    type: AssetMetadataResponseDto,
  })
  async verifyAsset(
    @Body() body: AdminVerifyAssetDto,
  ): Promise<AssetMetadataResponseDto> {
    this.logger.log(`Admin updating verification status for asset: ${body.code}`);
    return this.assetMetadataService.verifyAsset(
      body.code,
      body.issuer ?? null,
      body.verified,
      {
        type: body.type,
        decimals: body.decimals,
        iconUrl: body.iconUrl,
      },
    );
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
  @ApiQuery({
    name: "issuer",
    description: "Asset issuer public key (null/omitted for native XLM)",
    required: false,
  })
  @ApiResponse({
    status: 200,
    description: "Asset metadata refreshed successfully",
    type: AssetMetadataResponseDto,
  })
  async refreshAssetMetadata(
    @Param("code") code: string,
    @Query("issuer") issuer?: string,
  ): Promise<AssetMetadataResponseDto> {
    this.logger.log(`Refreshing metadata for asset: ${code} (issuer: ${issuer || "none"})`);
    return this.assetMetadataService.refreshAssetMetadata(code, issuer);
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
