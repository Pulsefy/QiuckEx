import {
  Body,
  Controller,
  Get,
  Headers,
  Param,
  Patch,
  Query,
} from '@nestjs/common';
import { ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';

import {
  EvaluateFeatureFlagResponseDto,
  FeatureFlagQueryDto,
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
  @ApiResponse({ type: EvaluateFeatureFlagResponseDto })
  async evaluateFlag(
    @Param('key') key: string,
    @Query() query: FeatureFlagQueryDto,
  ) {
    return this.featureFlagsService.evaluateFlag(key, query);
  }
}
