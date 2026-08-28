import {
  Body,
  Controller,
  ForbiddenException,
  Get,
  Headers,
  Param,
  Patch,
  Query,
  Req,
} from '@nestjs/common';
import { ApiHeader, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { Request } from 'express';

import {
  FeatureFlagQueryDto,
  FeatureFlagSnapshotQueryDto,
  FeatureFlagSnapshotResponseDto,
  UpdateFeatureFlagDto,
} from './feature-flags.dto';
import { FeatureFlagsService } from './feature-flags.service';
import { FlagAuditEntry } from '../audit/audit.model';
import { AuditService } from '../audit/audit.service';

/**
 * Resolve the actor identity for an admin write operation (issue #26).
 *
 * Priority:
 *  1. `req.apiKey.id`          — the authenticated API key ID (most trusted)
 *  2. `X-Admin-Actor` header   — fallback for trusted internal tooling
 *
 * Anonymous changes (no apiKey, no X-Admin-Actor header) are blocked.
 */
function resolveActor(
  req: Request,
  actorHeader: string | undefined,
): string {
  const apiKeyId = (req as unknown as Record<string, { id?: string }>)['apiKey']?.id;
  if (apiKeyId) return `apiKey:${apiKeyId}`;

  const headerActor = actorHeader?.trim();
  if (headerActor) return headerActor;

  throw new ForbiddenException({
    error: 'ANONYMOUS_CHANGE_BLOCKED',
    message:
      'Feature flag changes require an authenticated API key or an X-Admin-Actor header.',
  });
}

@ApiTags('feature-flags')
@ApiHeader({
  name: 'X-Admin-Actor',
  description:
    'Actor identity for audit attribution when an API key is not present. ' +
    'Required for admin write operations when no X-API-Key header is provided.',
  required: false,
})
@Controller()
export class FeatureFlagsController {
  constructor(
    private readonly featureFlagsService: FeatureFlagsService,
    private readonly auditService: AuditService,
  ) {}

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
  @ApiOperation({
    summary: 'Update a feature flag and audit the change',
    description:
      'Persists a feature-flag change and records a fully-attributed audit entry. ' +
      'Actor is resolved from the authenticated API key ID first, then the ' +
      '`X-Admin-Actor` header. Anonymous requests are rejected with 403.',
  })
  @ApiResponse({ status: 200, description: 'Feature flag updated successfully' })
  @ApiResponse({ status: 403, description: 'Anonymous changes are blocked' })
  async updateFlag(
    @Param('key') key: string,
    @Body() body: UpdateFeatureFlagDto,
    @Req() req: Request,
    @Headers('x-admin-actor') actorHeader?: string,
  ) {
    const actor = resolveActor(req, actorHeader);
    const current = await this.featureFlagsService.getFlagOrThrow(key);
    const updated = await this.featureFlagsService.updateFlag(key, body, actor);

    // Record the enriched audit entry (issue #26).
    const entry: FlagAuditEntry = {
      flagKey: key,
      previousValue: current,
      newValue: updated,
      actor,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
    };

    await this.auditService.log(
      actor,
      'feature_flag.updated',
      key,
      { flagAuditEntry: entry },
      (req as unknown as Record<string, string>)['correlationId'],
    );

    return updated;
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
