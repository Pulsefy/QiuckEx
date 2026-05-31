import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Post,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiParam, ApiResponse } from '@nestjs/swagger';

import { RequireScopes } from '../auth/decorators/require-scopes.decorator';
import { RateLimitGroupTag } from '../auth/decorators/rate-limit-group.decorator';
import { ContractChangeWebhookService } from './contract-change-webhook.service';

export class RegisterContractChangeWebhookDto {
  webhookUrl!: string;
  secret?: string;
}

export class ContractChangeWebhookResponseDto {
  id!: string;
  webhookUrl!: string;
  enabled!: boolean;
  createdAt!: string;
  updatedAt!: string;
}

@ApiTags('contracts')
@RateLimitGroupTag('authenticated')
@Controller('contracts/change-webhooks')
export class ContractChangeWebhooksController {
  constructor(
    private readonly contractChangeWebhookService: ContractChangeWebhookService,
  ) {}

  @Get()
  @RequireScopes('admin')
  @ApiOperation({
    summary: 'List registered contract change webhooks (admin only)',
    description:
      'Returns all webhook subscriptions that receive notifications when the contract registry is updated.',
  })
  @ApiResponse({ status: 200, type: [ContractChangeWebhookResponseDto] })
  list(): Promise<ContractChangeWebhookResponseDto[]> {
    return this.contractChangeWebhookService.listWebhooks();
  }

  @Post()
  @HttpCode(HttpStatus.CREATED)
  @RequireScopes('admin')
  @ApiOperation({
    summary: 'Register a contract change webhook (admin only)',
    description:
      'Subscribe to contract registry change events. The webhook will receive POST requests with a JSON payload describing publish and rollback events.',
  })
  @ApiResponse({ status: 201, type: ContractChangeWebhookResponseDto })
  @ApiResponse({ status: 400, description: 'Invalid webhook URL' })
  register(
    @Body() dto: RegisterContractChangeWebhookDto,
  ): Promise<ContractChangeWebhookResponseDto> {
    return this.contractChangeWebhookService.registerWebhook(
      dto.webhookUrl,
      dto.secret,
    );
  }

  @Delete(':id')
  @HttpCode(HttpStatus.NO_CONTENT)
  @RequireScopes('admin')
  @ApiOperation({
    summary: 'Unregister a contract change webhook (admin only)',
  })
  @ApiParam({ name: 'id', description: 'Webhook subscription ID' })
  @ApiResponse({ status: 204, description: 'Webhook deleted' })
  @ApiResponse({ status: 404, description: 'Webhook not found' })
  async unregister(@Param('id') id: string): Promise<void> {
    await this.contractChangeWebhookService.deleteWebhook(id);
  }
}