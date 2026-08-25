import {
  BadRequestException,
  Body,
  Controller,
  Get,
  Headers,
  HttpCode,
  HttpStatus,
  Param,
  ParseIntPipe,
  Post,
  Query,
  Req,
  ServiceUnavailableException,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import type { RawBodyRequest, Request } from 'express';
import { plainToInstance } from 'class-transformer';
import { validate } from 'class-validator';

import { AppConfigService } from '../config/app-config.service';
import { RequireScopes } from '../auth/decorators/require-scopes.decorator';
import { ApiKeyGuard } from '../auth/guards/api-key.guard';
import { RateLimitGroupTag } from '../auth/decorators/rate-limit-group.decorator';
import { mapValidationErrors } from '../common/utils/validation-error.mapper';
import { BranchDeploymentService } from './deployment-sync.service';
import { SyncBranchDeploymentDto } from './dto/sync-branch-deployment.dto';
import { BranchDeploymentResponseDto } from './dto/deployment-response.dto';
import { BranchDeployment } from './deployment-sync.model';
import { mapGithubDeploymentStatusEvent } from './github-deployment-status.mapper';
import { verifyGithubSignature } from './github-webhook-signature';

@ApiTags('deployments')
@Controller()
export class BranchDeploymentController {
  constructor(
    private readonly service: BranchDeploymentService,
    private readonly configService: AppConfigService,
  ) {}

  /**
   * Webhook ingestion for branch/PR deployment metadata (BE-60).
   *
   * Accepts either the normalized payload or a native GitHub
   * `deployment_status` event. Requests are authenticated with GitHub's
   * HMAC-SHA256 webhook signature (`X-Hub-Signature-256`).
   */
  @Post('deployments/webhook')
  @RateLimitGroupTag('webhooks')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Ingest branch/PR deployment metadata (GitHub webhook)',
    description:
      'Verified by X-Hub-Signature-256. Accepts both the normalized deployment payload and native GitHub deployment_status events.',
  })
  @ApiResponse({ status: 200, type: BranchDeploymentResponseDto })
  @ApiResponse({ status: 401, description: 'Invalid webhook signature' })
  @ApiResponse({ status: 503, description: 'GITHUB_WEBHOOK_SECRET not configured' })
  async webhook(
    @Req() req: RawBodyRequest<Request>,
    @Headers('x-hub-signature-256') signature?: string,
  ): Promise<BranchDeploymentResponseDto> {
    const secret = this.configService.githubWebhookSecret;
    if (!secret) {
      throw new ServiceUnavailableException({
        error: 'WEBHOOK_NOT_CONFIGURED',
        message: 'GITHUB_WEBHOOK_SECRET is not configured on this instance',
      });
    }

    if (!verifyGithubSignature(req.rawBody, signature, secret)) {
      throw new UnauthorizedException({
        error: 'INVALID_WEBHOOK_SIGNATURE',
        message: 'Invalid X-Hub-Signature-256',
      });
    }

    const body = req.body as unknown;
    const mapped = mapGithubDeploymentStatusEvent(body);
    const dto = mapped
      ? plainToInstance(SyncBranchDeploymentDto, {
          branchName: mapped.branchName,
          prNumber: mapped.prNumber,
          commitSha: mapped.commitSha,
          previewUrl: mapped.previewUrl,
          status: mapped.status,
          environment: mapped.environment,
          deliveredAt: mapped.deliveredAt,
        })
      : await this.toValidatedDto(body);

    const deployment = await this.service.syncDeployment(dto, 'github-webhook');
    return this.toResponse(deployment);
  }

  /**
   * Admin ingestion endpoint (BE-60). Enables polling-based ingestion:
   * a scheduler can fetch GitHub deployment state and push it here with an
   * admin-scoped API key.
   */
  @Post('admin/deployments/sync')
  @UseGuards(ApiKeyGuard)
  @RequireScopes('admin')
  @RateLimitGroupTag('authenticated')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Sync branch/PR deployment metadata (admin)',
    description:
      'Push deployment metadata for a branch/PR. Idempotent for duplicate deliveries; stale events are rejected with 409.',
  })
  @ApiResponse({ status: 200, type: BranchDeploymentResponseDto })
  @ApiResponse({ status: 409, description: 'Stale deployment event' })
  async sync(
    @Body() dto: SyncBranchDeploymentDto,
    @Req() req: Request,
  ): Promise<BranchDeploymentResponseDto> {
    const actor = req.apiKey?.id ?? 'admin';
    const deployment = await this.service.syncDeployment(dto, actor);
    return this.toResponse(deployment);
  }

  @Get('admin/deployments/branch/:branchName')
  @UseGuards(ApiKeyGuard)
  @RequireScopes('admin')
  @RateLimitGroupTag('authenticated')
  @ApiOperation({
    summary: 'Get latest deployment metadata for a branch (admin)',
    description:
      'Optionally scope the lookup to a pull request with ?pr=<number>.',
  })
  @ApiResponse({ status: 200, type: BranchDeploymentResponseDto })
  @ApiResponse({ status: 404, description: 'No deployment metadata found' })
  async getByBranch(
    @Param('branchName') branchName: string,
    @Query('pr') pr?: string,
  ): Promise<BranchDeploymentResponseDto> {
    const prNumber = pr !== undefined ? Number(pr) : undefined;
    const deployment = await this.service.getDeploymentByBranch(
      branchName,
      Number.isFinite(prNumber) ? prNumber : undefined,
    );
    return this.toResponse(deployment);
  }

  @Get('admin/deployments/pr/:prNumber')
  @UseGuards(ApiKeyGuard)
  @RequireScopes('admin')
  @RateLimitGroupTag('authenticated')
  @ApiOperation({
    summary: 'List deployment metadata for a pull request (admin)',
    description: 'Returns deployment history for the PR, newest first.',
  })
  @ApiResponse({ status: 200, type: [BranchDeploymentResponseDto] })
  async getByPr(
    @Param('prNumber', ParseIntPipe) prNumber: number,
    @Query('limit') limit?: string,
  ): Promise<BranchDeploymentResponseDto[]> {
    const parsedLimit = limit !== undefined ? Number(limit) : 20;
    const deployments = await this.service.getDeploymentsByPr(
      prNumber,
      Number.isFinite(parsedLimit) ? parsedLimit : 20,
    );
    return deployments.map((d) => this.toResponse(d));
  }

  private async toValidatedDto(body: unknown): Promise<SyncBranchDeploymentDto> {
    const dto = plainToInstance(SyncBranchDeploymentDto, body ?? {});
    const errors = await validate(dto, {
      whitelist: true,
      forbidNonWhitelisted: true,
    });
    if (errors.length > 0) {
      const mapped = mapValidationErrors(errors);
      throw new BadRequestException({
        code: 'VALIDATION_ERROR',
        message: mapped.message,
        fields: mapped.fields,
      });
    }
    return dto;
  }

  private toResponse(d: BranchDeployment): BranchDeploymentResponseDto {
    return {
      id: d.id,
      branchName: d.branchName,
      prNumber: d.prNumber,
      commitSha: d.commitSha,
      previewUrl: d.previewUrl,
      status: d.status,
      environment: d.environment,
      deliveredAt: d.deliveredAt.toISOString(),
      createdAt: d.createdAt.toISOString(),
      updatedAt: d.updatedAt.toISOString(),
    };
  }
}
