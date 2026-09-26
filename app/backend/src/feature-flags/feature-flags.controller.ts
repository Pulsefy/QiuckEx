import {
  Body,
  Controller,
  Get,
  Param,
  Patch,
  Query,
  Req,
  UseGuards,
} from '@nestjs/common';
import { ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { Request } from 'express';

import {
  FeatureFlagQueryDto,
  FeatureFlagSnapshotQueryDto,
  FeatureFlagSnapshotResponseDto,
  UpdateFeatureFlagDto,
} from './feature-flags.dto';
import { FeatureFlagsService } from './feature-flags.service';
import { RateLimitTier } from '../auth/decorators/rate-limit-group.decorator';
import { ApiKeyGuard } from '../auth/guards/api-key.guard';
import { RequireScopes } from '../auth/decorators/require-scopes.decorator';

/**
 * Express request enriched by `ApiKeyGuard`. The guard validates the
 * `x-api-key` header and attaches the resolved key record, which is the only
 * trustworthy source of actor identity for admin mutations.
 */
type AdminRequest = Request & {
  apiKey?: {
    id?: string;
    name?: string;
  };
};

/**
 * Derive the audited actor from the authenticated API key rather than a
 * client-supplied header. Falls back to a generic label only when the guard
 * did not attach a key (e.g. a route intentionally left public).
 */
function resolveAdminActor(req: AdminRequest): string {
  const name = req.apiKey?.name?.trim();
  if (name) return name;

  const id = req.apiKey?.id?.trim();
  if (id) return id;

  return 'admin-api';
}

@ApiTags('feature-flags')
@Controller()
export class FeatureFlagsController {
  constructor(private readonly featureFlagsService: FeatureFlagsService) {}

  @Get('admin/feature-flags')
  @UseGuards(ApiKeyGuard)
  @RequireScopes('admin')
  @RateLimitTier("public-read")
  @ApiOperation({ summary: 'List feature flags and flag store status' })
  async listFlags() {
    return this.featureFlagsService.listFlags();
  }

  @Get('admin/feature-flags/:key')
  @UseGuards(ApiKeyGuard)
  @RequireScopes('admin')
  @RateLimitTier("public-read")
  @ApiOperation({ summary: 'Get a single feature flag' })
  async getFlag(@Param('key') key: string) {
    return this.featureFlagsService.getFlagOrThrow(key);
  }

  @Patch('admin/feature-flags/:key')
  @UseGuards(ApiKeyGuard)
  @RequireScopes('admin')
  @RateLimitTier("mutation")
  @ApiOperation({ summary: 'Update a feature flag and audit the change' })
  @ApiResponse({ status: 200, description: 'Feature flag updated successfully' })
  async updateFlag(
    @Param('key') key: string,
    @Body() body: UpdateFeatureFlagDto,
    @Req() req: AdminRequest,
  ) {
    const actor = resolveAdminActor(req);
    return this.featureFlagsService.updateFlag(key, body, actor);
  }

  @Get('feature-flags/:key/evaluate')
  @RateLimitTier("public-read")
  @ApiOperation({ summary: 'Evaluate a feature flag for user/environment context' })
  async evaluateFlag(
    @Param('key') key: string,
    @Query() query: FeatureFlagQueryDto,
  ) {
    return this.featureFlagsService.evaluateFlag(key, query);
  }

  @Get('feature-flags/snapshot')
  @RateLimitTier("public-read")
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
