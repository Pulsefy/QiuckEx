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
import { ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { Request } from 'express';

import {
  FeatureFlagQueryDto,
  FeatureFlagSnapshotQueryDto,
  FeatureFlagSnapshotResponseDto,
  UpdateFeatureFlagDto,
} from './feature-flags.dto';
import { FeatureFlagsService } from './feature-flags.service';

@ApiTags('feature-flags')
@Controller()
export class FeatureFlagsController {
  constructor(private readonly featureFlagsService: FeatureFlagsService) {}

  @Get('admin/feature-flags')
  @ApiOperation({ summary: 'List feature flags and flag store status' })
  async listFlags() {
    return this.featureFlagsService.listFlags();
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
