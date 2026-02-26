import {
  Controller,
  Get,
  Put,
  Delete,
  Body,
  Param,
  HttpCode,
  HttpStatus,
  Logger,
} from "@nestjs/common";
import { ApiTags, ApiOperation, ApiResponse, ApiParam } from "@nestjs/swagger";

import { NotificationPreferencesRepository } from "./notification-preferences.repository";
import {
  UpsertNotificationPreferenceDto,
  NotificationPreferenceResponseDto,
} from "./dto/notification-preferences.dto";
import type { NotificationChannel } from "./types/notification.types";

/**
 * REST API for managing per-wallet notification preferences.
 *
 * Routes are keyed by Stellar public key (the wallet address), which serves
 * as the user identity throughout the system.
 *
 * Note: In production you would add the ApiKeyGuard here. For now it is
 * intentionally left open so mobile clients can register preferences without
 * a separate auth flow. Add `@UseGuards(ApiKeyGuard)` when ready.
 */
@ApiTags("Notifications")
@Controller("notifications/preferences")
export class NotificationPreferencesController {
  private readonly logger = new Logger(NotificationPreferencesController.name);

  constructor(private readonly prefsRepo: NotificationPreferencesRepository) {}

  /**
   * GET /notifications/preferences/:publicKey
   * List all notification preferences for a wallet.
   */
  @Get(":publicKey")
  @ApiOperation({ summary: "List notification preferences for a wallet" })
  @ApiParam({ name: "publicKey", description: "Stellar public key (G...)" })
  @ApiResponse({ status: 200, type: [NotificationPreferenceResponseDto] })
  async listPreferences(
    @Param("publicKey") publicKey: string,
  ): Promise<NotificationPreferenceResponseDto[]> {
    // Returns both enabled and disabled; client can filter as needed
    const all = await this.prefsRepo.getEnabledPreferences(publicKey);
    return all.map(this.toResponse);
  }

  /**
   * PUT /notifications/preferences/:publicKey
   * Create or update a channel preference for a wallet.
   */
  @Put(":publicKey")
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: "Create or update a notification channel preference",
  })
  @ApiParam({ name: "publicKey", description: "Stellar public key (G...)" })
  @ApiResponse({ status: 200, type: NotificationPreferenceResponseDto })
  async upsertPreference(
    @Param("publicKey") publicKey: string,
    @Body() dto: UpsertNotificationPreferenceDto,
  ): Promise<NotificationPreferenceResponseDto> {
    this.logger.log(
      `Upserting ${dto.channel} preference for ${publicKey.slice(0, 8)}...`,
    );

    const pref = await this.prefsRepo.upsertPreference(publicKey, dto.channel, {
      email: dto.email,
      pushToken: dto.pushToken,
      webhookUrl: dto.webhookUrl,
      events: dto.events ?? null,
      minAmountStroops:
        dto.minAmountStroops !== undefined
          ? BigInt(dto.minAmountStroops)
          : undefined,
      enabled: dto.enabled,
    });

    return this.toResponse(pref);
  }

  /**
   * DELETE /notifications/preferences/:publicKey/:channel
   * Opt-out of a specific notification channel (soft disable).
   */
  @Delete(":publicKey/:channel")
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: "Opt-out of a notification channel (soft disable)" })
  @ApiParam({ name: "publicKey", description: "Stellar public key (G...)" })
  @ApiParam({ name: "channel", enum: ["email", "push", "webhook"] })
  @ApiResponse({ status: 204, description: "Channel disabled" })
  async disableChannel(
    @Param("publicKey") publicKey: string,
    @Param("channel") channel: NotificationChannel,
  ): Promise<void> {
    this.logger.log(`Disabling ${channel} for ${publicKey.slice(0, 8)}...`);
    await this.prefsRepo.disableChannel(publicKey, channel);
  }

  // ---------------------------------------------------------------------------

  private toResponse(pref: {
    id: string;
    publicKey: string;
    channel: NotificationChannel;
    email?: string;
    pushToken?: string;
    webhookUrl?: string;
    events: string[] | null;
    minAmountStroops: bigint;
    enabled: boolean;
  }): NotificationPreferenceResponseDto {
    const dto = new NotificationPreferenceResponseDto();
    dto.id = pref.id;
    dto.publicKey = pref.publicKey;
    dto.channel = pref.channel;
    dto.email = pref.email;
    dto.pushToken = pref.pushToken;
    dto.webhookUrl = pref.webhookUrl;
    dto.events = pref.events as NotificationPreferenceResponseDto["events"];
    dto.minAmountStroops = pref.minAmountStroops.toString();
    dto.enabled = pref.enabled;
    return dto;
  }
}
