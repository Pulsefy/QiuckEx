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
  NotFoundException,
  ForbiddenException,
} from "@nestjs/common";
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiParam,
  ApiQuery,
} from "@nestjs/swagger";

import { WebhookService } from "./webhook.service";
import {
  CreateWebhookDto,
  UpdateWebhookDto,
  WebhookResponseDto,
  WebhookDeliveryLogDto,
  WebhookStatsDto,
  RedeliverWebhookDto,
  WebhookDeliveryStatusDto,
  WebhookReplayLogDto,
  WebhookRedeliverResponseDto,
} from "./dto/webhook.dto";
import { RateLimitGroupTag } from "../auth/decorators/rate-limit-group.decorator";

@ApiTags("Webhooks")
@RateLimitGroupTag("webhooks")
@Controller("webhooks")
export class WebhooksController {
  private readonly logger = new Logger(WebhooksController.name);

  constructor(private readonly webhookService: WebhookService) {}

  @Post(":publicKey")
  @ApiOperation({ summary: "Register a new webhook for payment events" })
  @ApiParam({
    name: "publicKey",
    description: "Stellar public key (G...)",
    example: "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN",
  })
  @ApiResponse({
    status: 201,
    description: "Webhook created successfully",
    type: WebhookResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: "Invalid webhook URL or parameters",
  })
  async createWebhook(
    @Param("publicKey") publicKey: string,
    @Body() dto: CreateWebhookDto,
  ): Promise<WebhookResponseDto> {
    this.logger.log(
      `Creating webhook for ${publicKey.slice(0, 8)}... -> ${dto.webhookUrl}`,
    );
    return this.webhookService.createWebhook(publicKey, dto);
  }

  @Get(":publicKey")
  @ApiOperation({ summary: "List all webhooks for a public key" })
  @ApiParam({
    name: "publicKey",
    description: "Stellar public key (G...)",
  })
  @ApiQuery({ name: 'cursor', required: false, description: 'Opaque pagination cursor' })
  @ApiQuery({ name: 'limit', required: false, type: Number, description: 'Items per page (1-100)' })
  @ApiResponse({
    status: 200,
    description: "List of webhooks",
    type: [WebhookResponseDto],
  })
  async listWebhooks(
    @Param("publicKey") publicKey: string,
    @Query('cursor') cursor?: string,
    @Query('limit') limit?: number,
  ) {
    return this.webhookService.listWebhooks(publicKey, cursor, Number(limit || 20));
  }

  @Get(":publicKey/:id")
  @ApiOperation({ summary: "Get webhook details by ID" })
  @ApiParam({ name: "publicKey", description: "Stellar public key (G...)" })
  @ApiParam({ name: "id", description: "Webhook ID (UUID)" })
  @ApiResponse({
    status: 200,
    description: "Webhook details",
    type: WebhookResponseDto,
  })
  @ApiResponse({ status: 404, description: "Webhook not found" })
  async getWebhook(
    @Param("publicKey") publicKey: string,
    @Param("id") id: string,
  ): Promise<WebhookResponseDto> {
    const webhook = await this.webhookService.getWebhook(id);
    if (!webhook) {
      throw new NotFoundException("Webhook not found");
    }
    if (webhook.publicKey !== publicKey) {
      throw new ForbiddenException(
        "Webhook does not belong to this public key",
      );
    }
    return webhook;
  }

  /**
   * PUT /webhooks/:publicKey/:id
   * Update a webhook.
   */
  @Put(":publicKey/:id")
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: "Update webhook configuration" })
  @ApiParam({ name: "publicKey", description: "Stellar public key (G...)" })
  @ApiParam({ name: "id", description: "Webhook ID (UUID)" })
  @ApiResponse({
    status: 200,
    description: "Webhook updated",
    type: WebhookResponseDto,
  })
  @ApiResponse({ status: 404, description: "Webhook not found" })
  async updateWebhook(
    @Param("publicKey") publicKey: string,
    @Param("id") id: string,
    @Body() dto: UpdateWebhookDto,
  ): Promise<WebhookResponseDto> {
    const webhook = await this.webhookService.updateWebhook(id, publicKey, dto);
    if (!webhook) {
      throw new NotFoundException("Webhook not found");
    }
    return webhook;
  }

  @Delete(":publicKey/:id")
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: "Delete a webhook" })
  @ApiParam({ name: "publicKey", description: "Stellar public key (G...)" })
  @ApiParam({ name: "id", description: "Webhook ID (UUID)" })
  @ApiResponse({ status: 204, description: "Webhook deleted" })
  @ApiResponse({ status: 404, description: "Webhook not found" })
  async deleteWebhook(
    @Param("publicKey") publicKey: string,
    @Param("id") id: string,
  ): Promise<void> {
    const deleted = await this.webhookService.deleteWebhook(id, publicKey);
    if (!deleted) {
      throw new NotFoundException("Webhook not found");
    }
    this.logger.log(`Deleted webhook ${id} for ${publicKey.slice(0, 8)}...`);
  }

  @Post(":publicKey/:id/regenerate-secret")
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: "Regenerate webhook secret",
    description:
      "Generate a new secret for signing webhook payloads. The old secret will immediately stop working.",
  })
  @ApiParam({ name: "publicKey", description: "Stellar public key (G...)" })
  @ApiParam({ name: "id", description: "Webhook ID (UUID)" })
  @ApiResponse({
    status: 200,
    description: "New secret generated",
    schema: {
      type: "object",
      properties: {
        secret: { type: "string", example: "whsec_xxxxxxxxxxxxxxxx" },
      },
    },
  })
  @ApiResponse({ status: 404, description: "Webhook not found" })
  async regenerateSecret(
    @Param("publicKey") publicKey: string,
    @Param("id") id: string,
  ): Promise<{ secret: string }> {
    const result = await this.webhookService.regenerateSecret(id, publicKey);
    if (!result) {
      throw new NotFoundException("Webhook not found");
    }
    this.logger.log(
      `Regenerated secret for webhook ${id} (${publicKey.slice(0, 8)}...)`,
    );
    return result;
  }

  @Get(":publicKey/:id/logs")
  @ApiOperation({ summary: "Get webhook delivery logs" })
  @ApiParam({ name: "publicKey", description: "Stellar public key (G...)" })
  @ApiParam({ name: "id", description: "Webhook ID (UUID)" })
  @ApiQuery({
    name: "limit",
    required: false,
    description: "Maximum number of logs to return",
    example: 50,
  })
  @ApiQuery({ name: 'cursor', required: false, description: 'Opaque pagination cursor' })
  @ApiResponse({
    status: 200,
    description: "Delivery logs",
    type: [WebhookDeliveryLogDto],
  })
  async getDeliveryLogs(
    @Param("publicKey") publicKey: string,
    @Param("id") id: string,
    @Query("limit") limit?: number,
    @Query('cursor') cursor?: string,
  ): Promise<{ data: WebhookDeliveryLogDto[]; next_cursor: string | null; has_more: boolean }> {
    const webhook = await this.webhookService.getWebhook(id);
    if (!webhook || webhook.publicKey !== publicKey) {
      throw new NotFoundException("Webhook not found");
    }

    return this.webhookService.getDeliveryLogs(publicKey, limit ? Number(limit) : undefined, cursor);
  }

  @Get(":publicKey/:id/stats")
  @ApiOperation({ summary: "Get webhook delivery statistics" })
  @ApiParam({ name: "publicKey", description: "Stellar public key (G...)" })
  @ApiParam({ name: "id", description: "Webhook ID (UUID)" })
  @ApiResponse({
    status: 200,
    description: "Webhook statistics",
    type: WebhookStatsDto,
  })
  async getStats(
    @Param("publicKey") publicKey: string,
    @Param("id") id: string,
  ): Promise<WebhookStatsDto> {
    const webhook = await this.webhookService.getWebhook(id);
    if (!webhook || webhook.publicKey !== publicKey) {
      throw new NotFoundException("Webhook not found");
    }

    return this.webhookService.getStats(publicKey);
  }

  @Post(":publicKey/:id/redeliver")
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: "Redeliver a specific event",
    description:
      "Trigger immediate redelivery of a previously failed or specific event. Rate-limited with per-event cooldown and per-webhook quotas to prevent replay storms.",
  })
  @ApiParam({ name: "publicKey", description: "Stellar public key (G...)" })
  @ApiParam({ name: "id", description: "Webhook ID (UUID)" })
  @ApiResponse({
    status: 200,
    description: "Redelivery triggered",
    type: WebhookRedeliverResponseDto,
  })
  @ApiResponse({ status: 404, description: "Webhook or delivery not found" })
  @ApiResponse({ status: 409, description: "Delivery already in progress" })
  @ApiResponse({ status: 429, description: "Replay cooldown or quota exceeded" })
  async redeliverEvent(
    @Param("publicKey") publicKey: string,
    @Param("id") id: string,
    @Body() dto: RedeliverWebhookDto,
  ): Promise<WebhookRedeliverResponseDto> {
    const webhook = await this.webhookService.getWebhook(id);
    if (!webhook || webhook.publicKey !== publicKey) {
      throw new NotFoundException("Webhook not found");
    }

    const result = await this.webhookService.redeliverEvent(
      publicKey,
      id,
      dto.eventId,
      dto.eventType,
    );

    this.logger.log(
      `Redeliver requested: ${dto.eventType}/${dto.eventId} for ${publicKey.slice(0, 8)}... -> ${result.deliverySuccess ? "succeeded" : "attempted"}`,
    );

    return result;
  }

  @Get(":publicKey/:id/deliveries/:eventType/:eventId")
  @ApiOperation({
    summary: "Get webhook delivery status for an event",
    description:
      "Visibility into retry schedule, last error, DLQ reason, and replay history for a specific event delivery.",
  })
  @ApiParam({ name: "publicKey", description: "Stellar public key (G...)" })
  @ApiParam({ name: "id", description: "Webhook ID (UUID)" })
  @ApiParam({ name: "eventType", description: "Event type" })
  @ApiParam({ name: "eventId", description: "Event ID" })
  @ApiResponse({
    status: 200,
    description: "Delivery status",
    type: WebhookDeliveryStatusDto,
  })
  @ApiResponse({ status: 404, description: "Webhook or delivery not found" })
  async getDeliveryStatus(
    @Param("publicKey") publicKey: string,
    @Param("id") id: string,
    @Param("eventType") eventType: string,
    @Param("eventId") eventId: string,
  ): Promise<WebhookDeliveryStatusDto> {
    const webhook = await this.webhookService.getWebhook(id);
    if (!webhook || webhook.publicKey !== publicKey) {
      throw new NotFoundException("Webhook not found");
    }

    return this.webhookService.getDeliveryStatus(publicKey, eventId, eventType);
  }

  @Get(":publicKey/:id/replays")
  @ApiOperation({
    summary: "List manual replay history for a webhook",
    description: "Queryable audit trail of replay API calls for this webhook.",
  })
  @ApiParam({ name: "publicKey", description: "Stellar public key (G...)" })
  @ApiParam({ name: "id", description: "Webhook ID (UUID)" })
  @ApiQuery({
    name: "limit",
    required: false,
    description: "Maximum replay log entries (1-100)",
    example: 50,
  })
  @ApiResponse({
    status: 200,
    description: "Replay audit log",
    type: [WebhookReplayLogDto],
  })
  async getReplayHistory(
    @Param("publicKey") publicKey: string,
    @Param("id") id: string,
    @Query("limit") limit?: number,
  ): Promise<WebhookReplayLogDto[]> {
    const webhook = await this.webhookService.getWebhook(id);
    if (!webhook || webhook.publicKey !== publicKey) {
      throw new NotFoundException("Webhook not found");
    }

    return this.webhookService.getReplayHistory(
      id,
      limit ? Number(limit) : undefined,
    );
  }
}
