import {
  Controller,
  Get,
  Post,
  Put,
  Delete,
  Body,
  Param,
  Query,
  HttpCode,
  HttpStatus,
  Logger,
  UseGuards,
  Req,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiQuery,
  ApiHeader,
} from '@nestjs/swagger';
import { Request } from 'express';

interface AuthenticatedRequest extends Request {
  user?: { id: string };
  correlationId?: string;
}

import { ApiKeyGuard } from '../auth/guards/api-key.guard';
import { RequireScopes } from '../auth/decorators/require-scopes.decorator';
import { RateLimitGroupTag } from '../auth/decorators/rate-limit-group.decorator';
import { BranchPreviewService } from './branch-preview.service';
import { BranchPreviewResponseDto } from './branch-preview.model';
import {
  CreateBranchPreviewRequestDto,
  UpdateBranchPreviewRequestDto,
} from './dto/admin-branch-preview.dto';

@ApiTags('branch-previews')
@ApiHeader({
  name: 'X-API-Key',
  description: 'API key for authentication',
  required: true,
})
@UseGuards(ApiKeyGuard)
@Controller()
export class BranchPreviewController {
  private readonly logger = new Logger(BranchPreviewController.name);

  constructor(private readonly branchPreviewService: BranchPreviewService) {}

  // Public endpoint to get preview environment for a branch
  @Get('preview/:branchName')
  @RateLimitGroupTag('public')
  @ApiOperation({
    summary: 'Get preview environment for a branch',
    description: 'Returns environment configuration for a specific branch preview, or fallback for unknown branches',
  })
  @ApiResponse({ status: 200, type: BranchPreviewResponseDto })
  async getBranchPreview(
    @Param('branchName') branchName: string,
  ): Promise<BranchPreviewResponseDto> {
    return this.branchPreviewService.getPreviewForBranch(branchName);
  }

  // Admin endpoints
  @Post('admin/branch-previews')
  @RequireScopes('admin')
  @RateLimitGroupTag('authenticated')
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({
    summary: 'Create a new branch preview mapping',
    description: 'Admin only: Create a new preview environment mapping for a branch',
  })
  async createBranchPreview(
    @Body() dto: CreateBranchPreviewRequestDto,
    @Req() req: AuthenticatedRequest,
  ) {
    const actorId = req.user?.id || 'unknown';
    const requestId = req.correlationId;
    return this.branchPreviewService.createPreview(dto, actorId, requestId);
  }

  @Put('admin/branch-previews/:id')
  @RequireScopes('admin')
  @RateLimitGroupTag('authenticated')
  @ApiOperation({
    summary: 'Update an existing branch preview mapping',
    description: 'Admin only: Update preview environment configuration',
  })
  async updateBranchPreview(
    @Param('id') id: string,
    @Body() dto: UpdateBranchPreviewRequestDto,
    @Req() req: AuthenticatedRequest,
  ) {
    const actorId = req.user?.id || 'unknown';
    const requestId = req.correlationId;
    return this.branchPreviewService.updatePreview(id, dto, actorId, requestId);
  }

  @Delete('admin/branch-previews/:id')
  @RequireScopes('admin')
  @RateLimitGroupTag('authenticated')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({
    summary: 'Delete a branch preview mapping',
    description: 'Admin only: Delete a preview environment mapping',
  })
  async deleteBranchPreview(
    @Param('id') id: string,
    @Req() req: AuthenticatedRequest,
  ) {
    const actorId = req.user?.id || 'unknown';
    const requestId = req.correlationId;
    return this.branchPreviewService.deletePreview(id, actorId, requestId);
  }

  @Get('admin/branch-previews')
  @RequireScopes('admin')
  @RateLimitGroupTag('authenticated')
  @ApiOperation({
    summary: 'List all branch preview mappings',
    description: 'Admin only: List all configured preview environments',
  })
  @ApiQuery({ name: 'includeInactive', required: false, type: Boolean })
  async listBranchPreviews(
    @Query('includeInactive') includeInactive?: boolean,
  ) {
    return this.branchPreviewService.listPreviews(includeInactive || false);
  }

  @Post('admin/branch-previews/:branchName/invalidate-cache')
  @RequireScopes('admin')
  @RateLimitGroupTag('authenticated')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Invalidate cache for a specific branch',
    description: 'Admin only: Force cache invalidation for a branch preview',
  })
  async invalidateBranchCache(
    @Param('branchName') branchName: string,
    @Req() req: AuthenticatedRequest,
  ) {
    const actorId = req.user?.id || 'unknown';
    const requestId = req.correlationId;
    const success = await this.branchPreviewService.invalidateCache(branchName, actorId, requestId);
    return { success };
  }

  @Post('admin/branch-previews/cache/clear')
  @RequireScopes('admin')
  @RateLimitGroupTag('authenticated')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Clear entire branch preview cache',
    description: 'Admin only: Clear all cached preview environments',
  })
  async clearAllCache(@Req() req: AuthenticatedRequest) {
    const actorId = req.user?.id || 'unknown';
    const requestId = req.correlationId;
    await this.branchPreviewService.clearAllCache(actorId, requestId);
    return { success: true };
  }

  @Post('admin/branch-previews/cleanup-expired')
  @RequireScopes('admin')
  @RateLimitGroupTag('authenticated')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Cleanup expired preview environments',
    description: 'Admin only: Deactivate all expired branch previews',
  })
  async cleanupExpired() {
    const count = await this.branchPreviewService.cleanupExpiredPreviews();
    return { deactivated: count };
  }
}