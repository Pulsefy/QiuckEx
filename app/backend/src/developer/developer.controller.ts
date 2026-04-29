import {
  Controller,
  Get,
  Post,
  Body,
  Param,
  Query,
  HttpCode,
  HttpStatus,
  ParseUUIDPipe,
  BadRequestException,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiParam,
  ApiQuery,
} from '@nestjs/swagger';

import { DeveloperService } from './developer.service';
import {
  BulkRevokeDto,
  BulkRevokeResultDto,
  WebhookTestResultDto,
  IntegrationHealthDto,
  PingResponseDto,
} from './dto/developer.dto';
import { ApiKeyCreated } from '../api-keys/api-keys.types';
import { RequireScopes } from '../auth/decorators/require-scopes.decorator';
import { RateLimitGroupTag } from '../auth/decorators/rate-limit-group.decorator';

@ApiTags('developer')
@RateLimitGroupTag('authenticated')
@Controller('developer')
export class DeveloperController {
  constructor(private readonly developerService: DeveloperService) {}

  @Get('ping')
  @ApiOperation({ summary: 'Connectivity check', description: 'Returns ok when the API is reachable. No authentication required.' })
  @ApiResponse({ status: 200, type: PingResponseDto })
  ping(): PingResponseDto {
    return this.developerService.ping();
  }

  @Post('webhooks/:webhookId/test')
  @HttpCode(HttpStatus.OK)
  @RequireScopes('admin')
  @ApiOperation({
    summary: 'Send a test event to a webhook receiver',
    description: 'Posts a synthetic payment.received event to the webhook URL so you can verify your receiver is reachable and correctly handling events.',
  })
  @ApiParam({ name: 'webhookId', description: 'Webhook UUID' })
  @ApiResponse({ status: 200, type: WebhookTestResultDto })
  @ApiResponse({ status: 404, description: 'Webhook not found' })
  testWebhook(
    @Param('webhookId', ParseUUIDPipe) webhookId: string,
  ): Promise<WebhookTestResultDto> {
    return this.developerService.testWebhook(webhookId);
  }

  @Post('keys/bulk-revoke')
  @HttpCode(HttpStatus.OK)
  @RequireScopes('admin')
  @ApiOperation({
    summary: 'Bulk revoke API keys',
    description: 'Revokes up to 100 API keys in a single request. Partial failures are reported per-key.',
  })
  @ApiResponse({ status: 200, type: BulkRevokeResultDto })
  bulkRevoke(@Body() dto: BulkRevokeDto): Promise<BulkRevokeResultDto> {
    return this.developerService.bulkRevoke(dto);
  }

  @Post('keys/:id/emergency-rotate')
  @HttpCode(HttpStatus.OK)
  @RequireScopes('admin')
  @ApiOperation({
    summary: 'Emergency key rotation',
    description: 'Rotates an API key and immediately invalidates the old key (no 24-hour grace period).',
  })
  @ApiParam({ name: 'id', description: 'API key UUID' })
  @ApiResponse({ status: 200, description: 'New key issued; store the raw key — it will not be shown again.' })
  @ApiResponse({ status: 404, description: 'API key not found' })
  emergencyRotate(
    @Param('id', ParseUUIDPipe) id: string,
  ): Promise<ApiKeyCreated> {
    return this.developerService.emergencyRotate(id);
  }

  @Get('health')
  @ApiOperation({
    summary: 'Integration health score',
    description: 'Returns a 0–100 score and letter grade based on webhook failure rate and API quota utilisation for a given organisation.',
  })
  @ApiQuery({ name: 'owner_id', required: true, description: 'Organisation / owner identifier (Stellar public key or user ID)' })
  @ApiResponse({ status: 200, type: IntegrationHealthDto })
  @ApiResponse({ status: 400, description: 'owner_id is required' })
  integrationHealth(@Query('owner_id') ownerId?: string): Promise<IntegrationHealthDto> {
    if (!ownerId) throw new BadRequestException('owner_id query parameter is required');
    return this.developerService.getIntegrationHealth(ownerId);
  }
}
