import { Module } from "@nestjs/common";

import { SupabaseModule } from "../supabase/supabase.module";
import { NotificationService } from "./notification.service";
import { NotificationPreferencesRepository } from "./notification-preferences.repository";
import { NotificationLogRepository } from "./notification-log.repository";
import { NotificationPreferencesController } from "./notification-preferences.controller";
import {
  NOTIFICATION_PROVIDERS,
  SendGridEmailProvider,
  ExpoPushProvider,
  WebhookProvider,
} from "./providers/notification-provider.interface";
import { TelegramRepository } from "./telegram/telegram.repository";
import { TelegramBotService } from "./telegram/telegram-bot.service";
import { TelegramNotificationProvider } from "./telegram/telegram.provider";
import { TelegramController } from "./telegram/telegram.controller";
import { WebhookService } from "./webhook.service";
import { WebhooksController } from "./webhooks.controller";

/**
 * Notification engine module.
 *
 * Provider configuration is driven by environment variables:
 *  - SENDGRID_API_KEY + SENDGRID_FROM_EMAIL  → enables email channel
 *  - EXPO_ACCESS_TOKEN (optional)            → enables push channel
 *  - TELEGRAM_BOT_TOKEN (optional)           → enables Telegram channel
 *  - Webhook channel is always registered (no credentials needed)
 *
 * ScheduleModule is registered once at AppModule level.
 */
@Module({
  imports: [SupabaseModule],
  controllers: [
    NotificationPreferencesController,
    TelegramController,
    WebhooksController,
  ],
  providers: [
    NotificationPreferencesRepository,
    NotificationLogRepository,
    TelegramRepository,
    TelegramBotService,
    TelegramNotificationProvider,
    WebhookService,
    {
      provide: NOTIFICATION_PROVIDERS,
      useFactory: (
        telegramBot: TelegramBotService,
        telegramRepo: TelegramRepository,
      ) => {
        const providers = [];

        const sendgridKey = process.env["SENDGRID_API_KEY"];
        const fromEmail = process.env["SENDGRID_FROM_EMAIL"];
        if (sendgridKey && fromEmail) {
          providers.push(new SendGridEmailProvider(sendgridKey, fromEmail));
        }

        providers.push(new ExpoPushProvider(process.env["EXPO_ACCESS_TOKEN"]));
        providers.push(new WebhookProvider());

        // Add Telegram provider if bot is initialized
        const telegramToken = process.env["TELEGRAM_BOT_TOKEN"];
        if (telegramToken) {
          providers.push(
            new TelegramNotificationProvider(telegramBot, telegramRepo),
          );
        }

        return providers;
      },
      inject: [TelegramBotService, TelegramRepository],
    },
    NotificationService,
  ],
  exports: [
    NotificationService,
    NotificationPreferencesRepository,
    TelegramRepository,
    TelegramBotService,
    TelegramNotificationProvider,
    WebhookService,
  ],
})
export class NotificationsModule {}

/**
 * Factory function to create Telegram provider with dependencies
 */
export function createTelegramProvider(
  telegramBot: TelegramBotService,
  telegramRepo: TelegramRepository,
): TelegramNotificationProvider {
  return new TelegramNotificationProvider(telegramBot, telegramRepo);
}
