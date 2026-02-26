import { Logger } from "@nestjs/common";
import type {
  NotificationChannel,
  NotificationPreference,
  BaseNotificationPayload,
} from "../types/notification.types";

// ---------------------------------------------------------------------------
// Provider interface
// ---------------------------------------------------------------------------

export interface ProviderSendResult {
  /** Provider-side message identifier for tracking. */
  messageId?: string;
}

export interface INotificationProvider {
  readonly channel: NotificationChannel;
  send(
    preference: NotificationPreference,
    payload: BaseNotificationPayload,
  ): Promise<ProviderSendResult>;
}

// ---------------------------------------------------------------------------
// SendGrid email provider
// ---------------------------------------------------------------------------

export class SendGridEmailProvider implements INotificationProvider {
  readonly channel: NotificationChannel = "email";
  private readonly logger = new Logger(SendGridEmailProvider.name);

  constructor(
    private readonly apiKey: string,
    private readonly fromEmail: string,
  ) {}

  async send(
    preference: NotificationPreference,
    payload: BaseNotificationPayload,
  ): Promise<ProviderSendResult> {
    if (!preference.email) {
      throw new Error("No email address configured for preference");
    }

    const body = {
      personalizations: [{ to: [{ email: preference.email }] }],
      from: { email: this.fromEmail },
      subject: payload.title,
      content: [
        {
          type: "text/plain",
          value: payload.body,
        },
        {
          type: "text/html",
          value: this.buildHtml(payload),
        },
      ],
    };

    const response = await fetch("https://api.sendgrid.com/v3/mail/send", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${this.apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      const text = await response.text();
      throw new Error(`SendGrid error ${response.status}: ${text}`);
    }

    // SendGrid returns X-Message-Id header
    const messageId = response.headers.get("X-Message-Id") ?? undefined;
    this.logger.debug(
      `Email sent to ${preference.email}: messageId=${messageId}`,
    );

    return { messageId };
  }

  private buildHtml(payload: BaseNotificationPayload): string {
    return `
      <h2>${payload.title}</h2>
      <p>${payload.body}</p>
      <hr/>
      <p style="color:#666;font-size:12px">QuickEx · ${payload.occurredAt}</p>
    `.trim();
  }
}

// ---------------------------------------------------------------------------
// Expo Push provider (React Native / mobile)
// ---------------------------------------------------------------------------

export class ExpoPushProvider implements INotificationProvider {
  readonly channel: NotificationChannel = "push";
  private readonly logger = new Logger(ExpoPushProvider.name);

  // Optional server-side Expo access token for priority push
  constructor(private readonly accessToken?: string) {}

  async send(
    preference: NotificationPreference,
    payload: BaseNotificationPayload,
  ): Promise<ProviderSendResult> {
    if (!preference.pushToken) {
      throw new Error("No push token configured for preference");
    }

    const message = {
      to: preference.pushToken,
      title: payload.title,
      body: payload.body,
      data: {
        eventType: payload.eventType,
        eventId: payload.eventId,
        ...(payload.metadata ?? {}),
      },
      sound: "default",
      priority: "high",
    };

    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      Accept: "application/json",
    };

    if (this.accessToken) {
      headers["Authorization"] = `Bearer ${this.accessToken}`;
    }

    const response = await fetch("https://exp.host/--/api/v2/push/send", {
      method: "POST",
      headers,
      body: JSON.stringify(message),
    });

    if (!response.ok) {
      const text = await response.text();
      throw new Error(`Expo Push error ${response.status}: ${text}`);
    }

    const json = (await response.json()) as { data?: { id?: string } };
    const messageId = json.data?.id;
    this.logger.debug(
      `Push sent to ${preference.pushToken}: messageId=${messageId}`,
    );

    return { messageId };
  }
}

// ---------------------------------------------------------------------------
// Webhook provider
// ---------------------------------------------------------------------------

export class WebhookProvider implements INotificationProvider {
  readonly channel: NotificationChannel = "webhook";
  private readonly logger = new Logger(WebhookProvider.name);

  async send(
    preference: NotificationPreference,
    payload: BaseNotificationPayload,
  ): Promise<ProviderSendResult> {
    if (!preference.webhookUrl) {
      throw new Error("No webhook URL configured for preference");
    }

    const body = {
      eventType: payload.eventType,
      eventId: payload.eventId,
      title: payload.title,
      body: payload.body,
      occurredAt: payload.occurredAt,
      recipientPublicKey: payload.recipientPublicKey,
      metadata: payload.metadata ?? {},
    };

    const response = await fetch(preference.webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      throw new Error(
        `Webhook returned HTTP ${response.status} for ${preference.webhookUrl}`,
      );
    }

    this.logger.debug(`Webhook delivered to ${preference.webhookUrl}`);
    return {};
  }
}

// ---------------------------------------------------------------------------
// Token for DI
// ---------------------------------------------------------------------------

export const NOTIFICATION_PROVIDERS = Symbol("NOTIFICATION_PROVIDERS");
