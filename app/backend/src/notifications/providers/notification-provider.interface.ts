import { Logger } from "@nestjs/common";
import * as crypto from "crypto";

import type {
  NotificationChannel,
  NotificationPreference,
  BaseNotificationPayload,
  WebhookPayload,
} from "../types/notification.types";

// ---------------------------------------------------------------------------
// Provider interface
// ---------------------------------------------------------------------------

export interface ProviderSendResult {
  messageId?: string;
  httpStatus?: number;
  responseBody?: string;
}

export interface INotificationProvider {
  readonly channel: NotificationChannel;
  send(
    preference: NotificationPreference,
    payload: BaseNotificationPayload,
  ): Promise<ProviderSendResult>;
}

// ---------------------------------------------------------------------------
// No-op provider for local / development transports
// ---------------------------------------------------------------------------
export class NoopNotificationProvider implements INotificationProvider {
  readonly channel: NotificationChannel;
  private readonly logger = new Logger(NoopNotificationProvider.name);

  constructor(channel: NotificationChannel) {
    this.channel = channel;
  }

  async send(
    preference: NotificationPreference,
    payload: BaseNotificationPayload,
  ): Promise<ProviderSendResult> {
    this.logger.debug(
      `[noop:${this.channel}] simulated notification for ${payload.eventType} to ${preference.publicKey}`,
    );
    return {
      messageId: `noop:${payload.eventId}`,
      httpStatus: 200,
      responseBody: "noop",
    };
  }
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
  private readonly maxResponseBodyLength = 1000;

  async send(
    preference: NotificationPreference,
    payload: BaseNotificationPayload,
  ): Promise<ProviderSendResult> {
    if (!preference.webhookUrl) {
      throw new Error("No webhook URL configured for preference");
    }

    const webhookPayload = this.buildWebhookPayload(payload);
    const body = JSON.stringify(webhookPayload);
    const signature = this.signPayload(body, webhookPayload.sentAt, preference.webhookSecret);

    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      "X-QuickEx-Signature": signature,
      "X-QuickEx-Delivery": webhookPayload.id,
      "X-QuickEx-Event": payload.eventType,
      "X-QuickEx-Timestamp": webhookPayload.sentAt,
    };

    const response = await fetch(preference.webhookUrl, {
      method: "POST",
      headers,
      body,
    });

    let responseBody: string | undefined;
    try {
      const text = await response.text();
      responseBody =
        text.length > this.maxResponseBodyLength
          ? text.slice(0, this.maxResponseBodyLength) + "..."
          : text;
    } catch {
      // Ignore response body read errors
    }

    if (!response.ok) {
      throw new Error(
        `Webhook returned HTTP ${response.status} for ${preference.webhookUrl}: ${responseBody ?? "no response body"}`,
      );
    }

    this.logger.debug(
      `Webhook delivered to ${preference.webhookUrl}: status=${response.status}`,
    );

    return {
      httpStatus: response.status,
      responseBody,
    };
  }

  private buildWebhookPayload(
    payload: BaseNotificationPayload,
  ): WebhookPayload {
    const deliveryId = `wh_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;

    return {
      id: deliveryId,
      eventType: payload.eventType,
      eventId: payload.eventId,
      timestamp: payload.occurredAt,
      sentAt: new Date().toISOString(),
      recipientPublicKey: payload.recipientPublicKey,
      title: payload.title,
      body: payload.body,
      data: payload.metadata ?? {},
    };
  }

  private signPayload(body: string, timestamp: string, secret?: string): string {
    if (!secret) {
      this.logger.warn(
        "Webhook secret not configured - payload will not be signed",
      );
      return "";
    }

    // Sign timestamp + "." + body to prevent replay attacks
    const hmac = crypto.createHmac("sha256", secret);
    hmac.update(`${timestamp}.${body}`);
    const digest = hmac.digest("hex");
    return `sha256=${digest}`;
  }

  /**
   * Verify an incoming webhook signature.
   * @param body Raw request body string
   * @param signature Value of X-QuickEx-Signature header
   * @param timestamp Value of X-QuickEx-Timestamp header
   * @param secret Shared webhook secret
   * @param toleranceMs Replay window in ms (default 5 minutes)
   */
  static verifySignature(
    body: string,
    signature: string,
    timestamp: string,
    secret: string,
    toleranceMs = 5 * 60 * 1000,
  ): boolean {
    if (!signature.startsWith("sha256=")) {
      return false;
    }

    // Reject stale timestamps to prevent replay attacks
    const ts = new Date(timestamp).getTime();
    if (isNaN(ts) || Math.abs(Date.now() - ts) > toleranceMs) {
      return false;
    }

    const expectedDigest = signature.slice(7);
    const hmac = crypto.createHmac("sha256", secret);
    hmac.update(`${timestamp}.${body}`);
    const actualDigest = hmac.digest("hex");

    try {
      return crypto.timingSafeEqual(
        Buffer.from(expectedDigest, "hex"),
        Buffer.from(actualDigest, "hex"),
      );
    } catch {
      return false;
    }
  }
}

// ---------------------------------------------------------------------------
// Token for DI
// ---------------------------------------------------------------------------

export const NOTIFICATION_PROVIDERS = Symbol("NOTIFICATION_PROVIDERS");
