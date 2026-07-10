import { Body, Controller, Get, HttpCode, HttpStatus, Param, Post, Query, Req, UseGuards } from '@nestjs/common';
import { ApiHeader, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import type { Request } from 'express';

import { ApiKeyGuard } from '../auth/guards/api-key.guard';
import { RequireScopes } from '../auth/decorators/require-scopes.decorator';
import { DeploymentArtifactsService } from './deployment-artifacts.service';
import {
  DeploymentArtifactDownloadResponseDto,
  DeploymentArtifactResponseDto,
  ListDeploymentArtifactsQueryDto,
  UploadDeploymentArtifactDto,
} from './dto/deployment-artifact.dto';

@ApiTags('contracts')
@ApiHeader({
  name: 'X-API-Key',
  description: 'Admin-scoped API key required for all deployment artifact operations.',
  required: true,
})
@UseGuards(ApiKeyGuard)
@Controller('contracts/deployment-artifacts')
export class DeploymentArtifactsController {
  constructor(private readonly artifacts: DeploymentArtifactsService) {}

  @Post()
  @HttpCode(HttpStatus.CREATED)
  @RequireScopes('admin')
  @ApiOperation({ summary: 'Upload a signed deployment artifact' })
  @ApiResponse({ status: 201, type: DeploymentArtifactResponseDto })
  async upload(
    @Body() dto: UploadDeploymentArtifactDto,
    @Req() req: Request,
  ): Promise<DeploymentArtifactResponseDto> {
    const uploadedBy = req.apiKey?.id ?? 'api';
    return this.artifacts.upload(dto, uploadedBy);
  }

  @Get()
  @RequireScopes('admin')
  @ApiOperation({ summary: 'List deployment artifacts, optionally filtered by deployment or type' })
  @ApiResponse({ status: 200, type: [DeploymentArtifactResponseDto] })
  async list(
    @Query() query: ListDeploymentArtifactsQueryDto,
  ): Promise<DeploymentArtifactResponseDto[]> {
    return this.artifacts.list({
      deploymentId: query.deploymentId,
      artifactType: query.artifactType,
    });
  }

  @Get(':id')
  @RequireScopes('admin')
  @ApiOperation({ summary: 'Download a deployment artifact by id, with checksum verification' })
  @ApiResponse({ status: 200, type: DeploymentArtifactDownloadResponseDto })
  @ApiResponse({ status: 404, description: 'Artifact not found' })
  async download(@Param('id') id: string): Promise<DeploymentArtifactDownloadResponseDto> {
    return this.artifacts.download(id);
  }
}
