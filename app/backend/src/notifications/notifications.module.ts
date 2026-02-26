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

/**
 * Notification engine module.
 *
 * Provider configuration is driven by environment variables:
 *  - SENDGRID_API_KEY + SENDGRID_FROM_EMAIL  → enables email channel
 *  - EXPO_ACCESS_TOKEN (optional)            → enables push channel
 *  - Webhook channel is always registered (no credentials needed)
 *
 * ScheduleModule is registered once at AppModule level.
 */
@Module({
  imports: [SupabaseModule],
  controllers: [NotificationPreferencesController],
  providers: [
    NotificationPreferencesRepository,
    NotificationLogRepository,
    {
      provide: NOTIFICATION_PROVIDERS,
      useFactory: () => {
        const providers = [];

        const sendgridKey = process.env["SENDGRID_API_KEY"];
        const fromEmail = process.env["SENDGRID_FROM_EMAIL"];
        if (sendgridKey && fromEmail) {
          providers.push(new SendGridEmailProvider(sendgridKey, fromEmail));
        }

        providers.push(new ExpoPushProvider(process.env["EXPO_ACCESS_TOKEN"]));
        providers.push(new WebhookProvider());

        return providers;
      },
    },
    NotificationService,
  ],
  exports: [NotificationService, NotificationPreferencesRepository],
})
export class NotificationsModule {}
