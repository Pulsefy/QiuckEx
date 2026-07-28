import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Post,
  Query,
  Req,
  UseGuards,
} from '@nestjs/common';
import { ApiHeader, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import type { Request } from 'express';

import { ApiKeyGuard } from '../auth/guards/api-key.guard';
import { RequireScopes } from '../auth/decorators/require-scopes.decorator';
import { SupportBundleReferenceService } from './support-bundle-reference.service';
import {
  CreateSupportBundleReferenceDto,
  ListSupportBundleReferencesQueryDto,
  SupportBundleReferenceResponseDto,
} from './dto/support-bundle-reference.dto';

@ApiTags('Support Bundle References')
@ApiHeader({
  name: 'X-API-Key',
  description: 'API key scoped to support:read/support:write is required for these operations.',
  required: true,
})
@UseGuards(ApiKeyGuard)
@Controller('support/bundle-references')
export class SupportBundleReferenceController {
  constructor(private readonly references: SupportBundleReferenceService) {}

  @Post()
  @HttpCode(HttpStatus.CREATED)
  @RequireScopes('support:write')
  @ApiOperation({
    summary: 'Attach a support bundle id to an issue report or receipt',
    description:
      'Creates a reference linking a previously generated support bundle to an issue report ' +
      'or receipt, so support staff can locate diagnostics without the client re-uploading them. ' +
      'The reference expires automatically (default 30 days, max 90).',
  })
  @ApiResponse({ status: 201, type: SupportBundleReferenceResponseDto })
  async create(
    @Body() dto: CreateSupportBundleReferenceDto,
    @Req() req: Request,
  ): Promise<SupportBundleReferenceResponseDto> {
    const createdBy = req.apiKey?.id ?? 'api';
    return this.references.create(dto, createdBy);
  }

  @Get()
  @RequireScopes('support:read')
  @ApiOperation({
    summary: 'Look up support bundle references attached to an issue report or receipt',
    description: 'Returns non-expired, non-redacted references. Bundle ids are always masked.',
  })
  @ApiResponse({ status: 200, type: [SupportBundleReferenceResponseDto] })
  async findByTarget(
    @Query() query: ListSupportBundleReferencesQueryDto,
  ): Promise<SupportBundleReferenceResponseDto[]> {
    return this.references.findByTarget(query.targetType, query.targetId);
  }

  @Get(':id')
  @RequireScopes('support:read')
  @ApiOperation({ summary: 'Get a single support bundle reference by id' })
  @ApiResponse({ status: 200, type: SupportBundleReferenceResponseDto })
  @ApiResponse({ status: 404, description: 'Reference not found, expired, or redacted' })
  async findById(@Param('id') id: string): Promise<SupportBundleReferenceResponseDto> {
    return this.references.findById(id);
  }

  @Post(':id/redact')
  @HttpCode(HttpStatus.OK)
  @RequireScopes('admin')
  @ApiOperation({ summary: 'Manually redact a support bundle reference ahead of its expiry' })
  @ApiResponse({ status: 200, type: SupportBundleReferenceResponseDto })
  @ApiResponse({ status: 404, description: 'Reference not found' })
  async redact(
    @Param('id') id: string,
    @Req() req: Request,
  ): Promise<SupportBundleReferenceResponseDto> {
    const redactedBy = req.apiKey?.id ?? 'api';
    return this.references.redact(id, redactedBy);
  }
}
