import {
  Controller,
  Post,
  Get,
  Body,
  Param,
  UseGuards,
  HttpCode,
  HttpStatus,
  ParseIntPipe,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth, ApiParam } from '@nestjs/swagger';
import { DeploymentSyncService } from './deployment-sync.service';
import { DeploymentWebhookPayloadDto } from './dto/webhook-payload.dto';
import { DeploymentResponseDto } from './dto/deployment-response.dto';
import { ApiKeyGuard } from '../auth/guards/api-key.guard';
import { RequireScopes } from '../auth/decorators/require-scopes.decorator';

@ApiTags('Deployment Metadata Sync')
@Controller()
export class DeploymentSyncController {
  constructor(private readonly deploymentSyncService: DeploymentSyncService) {}

  @Post('deployment-sync/webhook')
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({
    summary: 'Ingest deployment metadata from GitHub or Vercel webhooks',
    description:
      'Receives branch name, PR number, commit SHA, preview URL, and status. ' +
      'Idempotent and discards stale updates based on event timestamps.',
  })
  @ApiResponse({
    status: 201,
    description: 'Deployment metadata successfully synced',
    type: DeploymentResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Bad request - invalid payload details',
  })
  async syncDeployment(
    @Body() payload: DeploymentWebhookPayloadDto
  ): Promise<DeploymentResponseDto> {
    return this.deploymentSyncService.syncDeployment(payload);
  }

  @Get('admin/deployments/branch/:branchName')
  @UseGuards(ApiKeyGuard)
  @RequireScopes('admin')
  @ApiBearerAuth()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Query deployment metadata by branch name (Admin only)',
    description: 'Retrieves the latest deployment metadata synced for the specified branch name.',
  })
  @ApiParam({
    name: 'branchName',
    type: String,
    description: 'The Git branch name to query metadata for',
  })
  @ApiResponse({
    status: 200,
    description: 'Successfully retrieved deployment metadata',
    type: DeploymentResponseDto,
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - invalid or missing API key',
  })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - insufficient scopes (requires admin)',
  })
  @ApiResponse({
    status: 404,
    description: 'Deployment metadata not found for this branch name',
  })
  async getDeploymentByBranch(
    @Param('branchName') branchName: string
  ): Promise<DeploymentResponseDto> {
    return this.deploymentSyncService.getDeploymentByBranch(branchName);
  }

  @Get('admin/deployments/pr/:prNumber')
  @UseGuards(ApiKeyGuard)
  @RequireScopes('admin')
  @ApiBearerAuth()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Query deployment metadata by PR number (Admin only)',
    description:
      'Retrieves all deployment metadata entries synced for the specified pull request number.',
  })
  @ApiParam({
    name: 'prNumber',
    type: Number,
    description: 'The pull request number to query metadata for',
  })
  @ApiResponse({
    status: 200,
    description: 'Successfully retrieved list of deployment metadata entries',
    type: [DeploymentResponseDto],
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - invalid or missing API key',
  })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - insufficient scopes (requires admin)',
  })
  @ApiResponse({
    status: 404,
    description: 'Deployment metadata not found for this PR number',
  })
  async getDeploymentsByPr(
    @Param('prNumber', ParseIntPipe) prNumber: number
  ): Promise<DeploymentResponseDto[]> {
    return this.deploymentSyncService.getDeploymentsByPr(prNumber);
  }
}
