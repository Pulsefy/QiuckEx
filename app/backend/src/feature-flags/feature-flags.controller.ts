import {
  Body,
  Controller,
  Get,
  Headers,
  Param,
  Patch,
  Query,
  Req,
} from '@nestjs/common';
import { ApiBody, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { IsNumber, IsOptional, Min } from 'class-validator';
import { ApiPropertyOptional } from '@nestjs/swagger';
import { Request } from 'express';

import {
  FeatureFlagQueryDto,
  FeatureFlagSnapshotQueryDto,
  FeatureFlagSnapshotResponseDto,
  UpdateFeatureFlagDto,
} from './feature-flags.dto';
import { FeatureFlagsService } from './feature-flags.service';

/** DTO for updating the username search ranking weights. */
class UpdateRankingWeightsDto {
  @ApiPropertyOptional({
    description: 'Weight for fuzzy similarity score (pg_trgm). Must be ≥ 0.',
    example: 1,
  })
  @IsOptional()
  @IsNumber()
  @Min(0)
  similarity?: number;

  @ApiPropertyOptional({
    description: 'Weight for historical transaction volume. Must be ≥ 0.',
    example: 0.5,
  })
  @IsOptional()
  @IsNumber()
  @Min(0)
  transactionVolume?: number;

  @ApiPropertyOptional({
    description: 'Weight for recency (last_active_at). Must be ≥ 0.',
    example: 1,
  })
  @IsOptional()
  @IsNumber()
  @Min(0)
  lastActiveAt?: number;

  @ApiPropertyOptional({
    description: 'Weight for featured-profile boost. Must be ≥ 0.',
    example: 2,
  })
  @IsOptional()
  @IsNumber()
  @Min(0)
  isFeatured?: number;
}

@ApiTags('feature-flags')
@Controller()
export class FeatureFlagsController {
  constructor(private readonly featureFlagsService: FeatureFlagsService) {}

  @Get('admin/feature-flags')
  @ApiOperation({ summary: 'List feature flags and flag store status' })
  async listFlags() {
    return this.featureFlagsService.listFlags();
  }

  @Patch('admin/feature-flags/username.ranking_weights')
  @ApiOperation({
    summary: 'Update username search ranking weights',
    description:
      'Updates the `username.ranking_weights` feature flag metadata with new ranking ' +
      'weights. Weights are relative—they are normalised internally before scoring so ' +
      'the caller need not ensure they sum to 1. ' +
      '\n\n**Ranking formula (after normalisation):**\n' +
      '```\n' +
      'score = w_similarity   * normalizedSimilarity\n' +
      '      + w_txVolume     * normalizedTxVolume\n' +
      '      + w_lastActiveAt * normalizedRecency\n' +
      '      + w_isFeatured   * (isFeatured ? 1 : 0)\n' +
      '```\n' +
      'Changes take effect within 60 seconds (cache TTL).',
  })
  @ApiBody({ type: UpdateRankingWeightsDto })
  @ApiResponse({ status: 200, description: 'Ranking weights updated' })
  async updateRankingWeights(
    @Body() body: UpdateRankingWeightsDto,
    @Headers('x-admin-actor') actorHeader?: string,
  ) {
    const actor = actorHeader?.trim() || 'admin-ui';
    const FLAG_KEY = 'username.ranking_weights';
    // Load the current flag so we can merge the incoming partial weights into
    // the existing metadata rather than replacing unmentioned keys.
    const current = await this.featureFlagsService.getFlagOrThrow(FLAG_KEY);
    const currentMeta = (current.metadata ?? {}) as Record<string, unknown>;
    const mergedMeta: Record<string, unknown> = {
      ...currentMeta,
      ...(body.similarity !== undefined ? { similarity: body.similarity } : {}),
      ...(body.transactionVolume !== undefined ? { transactionVolume: body.transactionVolume } : {}),
      ...(body.lastActiveAt !== undefined ? { lastActiveAt: body.lastActiveAt } : {}),
      ...(body.isFeatured !== undefined ? { isFeatured: body.isFeatured } : {}),
    };
    return this.featureFlagsService.updateFlag(FLAG_KEY, { metadata: mergedMeta }, actor);
  }

  @Get('admin/feature-flags/:key')
  @ApiOperation({ summary: 'Get a single feature flag' })
  async getFlag(@Param('key') key: string) {
    return this.featureFlagsService.getFlagOrThrow(key);
  }

  @Patch('admin/feature-flags/:key')
  @ApiOperation({ summary: 'Update a feature flag and audit the change' })
  @ApiResponse({ status: 200, description: 'Feature flag updated successfully' })
  async updateFlag(
    @Param('key') key: string,
    @Body() body: UpdateFeatureFlagDto,
    @Headers('x-admin-actor') actorHeader?: string,
  ) {
    const actor = actorHeader?.trim() || 'admin-ui';
    return this.featureFlagsService.updateFlag(key, body, actor);
  }

  @Get('feature-flags/:key/evaluate')
  @ApiOperation({ summary: 'Evaluate a feature flag for user/environment context' })
  async evaluateFlag(
    @Param('key') key: string,
    @Query() query: FeatureFlagQueryDto,
  ) {
    return this.featureFlagsService.evaluateFlag(key, query);
  }

  @Get('feature-flags/snapshot')
  @ApiOperation({
    summary: 'Feature flag snapshot',
    description:
      'Returns a read-only snapshot of effective feature flags for clients and admin tooling. ' +
      'Sensitive/internal flags are excluded. When X-Preview-Scope header is present, ' +
      'preview override status is included.',
  })
  async getSnapshot(
    @Query() query: FeatureFlagSnapshotQueryDto,
    @Req() req: Request,
  ): Promise<FeatureFlagSnapshotResponseDto> {
    return this.featureFlagsService.getSnapshot(
      query.environment,
      req.previewScope,
    );
  }
}
