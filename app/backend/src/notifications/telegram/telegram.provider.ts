import { Injectable, Logger } from "@nestjs/common";
import {
  INotificationProvider,
  ProviderSendResult,
} from "../providers/notification-provider.interface";
import type {
  NotificationChannel,
  NotificationPreference,
  BaseNotificationPayload,
} from "../types/notification.types";
import { TelegramBotService } from "./telegram-bot.service";
import { TelegramRepository } from "./telegram.repository";

@Injectable()
export class TelegramNotificationProvider implements INotificationProvider {
  readonly channel: NotificationChannel = "telegram";
  private readonly logger = new Logger(TelegramNotificationProvider.name);

  constructor(
    private readonly telegramBot: TelegramBotService,
    private readonly telegramRepo: TelegramRepository,
  ) {}

  async send(
    preference: NotificationPreference,
    payload: BaseNotificationPayload,
  ): Promise<ProviderSendResult> {
    // Find the Telegram mapping for this public key
    const mapping = await this.telegramRepo.findByPublicKey(
      preference.publicKey,
    );

    if (!mapping) {
      throw new Error(
        `No Telegram mapping found for public key ${preference.publicKey}`,
      );
    }

    if (!mapping.isVerified) {
      throw new Error(
        `Telegram account for ${preference.publicKey} is not verified`,
      );
    }

    if (!mapping.enabled) {
      this.logger.debug(
        `Notifications disabled for Telegram user ${mapping.telegramId}`,
      );
      return { messageId: undefined };
    }

    // Check minimum amount threshold
    if (
      payload.amountStroops !== undefined &&
      payload.amountStroops < mapping.minAmountStroops
    ) {
      this.logger.debug(
        `Payment amount ${payload.amountStroops} below threshold ${mapping.minAmountStroops} for Telegram user ${mapping.telegramId}`,
      );
      return { messageId: undefined };
    }

    // Format the notification message
    const title = payload.title;
    const body = this.formatMessageBody(payload);

    // Send the notification
    const messageId = await this.telegramBot.sendNotification(
      mapping.telegramId,
      title,
      body,
      payload.metadata,
    );

    // Update last notification timestamp
    await this.telegramRepo.updateLastNotification(mapping.telegramId);

    // Log the delivery
    await this.telegramRepo.logNotification({
      telegramId: mapping.telegramId,
      publicKey: preference.publicKey,
      eventType: payload.eventType,
      eventId: payload.eventId,
      status: "sent",
      telegramMessageId: messageId ?? undefined,
    });

    this.logger.debug(
      `Telegram notification sent to ${mapping.telegramId} for event ${payload.eventType}`,
    );

    return { messageId: messageId?.toString() };
  }

  /**
   * Format the message body for Telegram notifications
   */
  private formatMessageBody(payload: BaseNotificationPayload): string {
    let body = payload.body;

    // Add metadata details if available
    if (payload.metadata) {
      const details: string[] = [];

      if ("txHash" in payload.metadata && payload.metadata.txHash) {
        const txHash = payload.metadata.txHash as string;
        details.push(`Transaction: \`${this.truncate(txHash, 8)}...\``);
      }

      if ("sender" in payload.metadata && payload.metadata.sender) {
        const sender = payload.metadata.sender as string;
        details.push(`From: \`${this.truncate(sender, 8)}...\``);
      }

      if ("commitment" in payload.metadata && payload.metadata.commitment) {
        const commitment = payload.metadata.commitment as string;
        details.push(`Commitment: \`${this.truncate(commitment, 8)}...\``);
      }

      if (details.length > 0) {
        body += "\n\n" + details.join("\n");
      }
    }

    // Add timestamp footer
    const timeStr = new Date(payload.occurredAt).toLocaleString();
    body += `\n\n⏰ ${timeStr}`;

    return body;
  }

  /**
   * Truncate a string to specified length
   */
  private truncate(str: string, length: number): string {
    if (!str || str.length <= length) return str;
    return str.substring(0, length);
  }
}
