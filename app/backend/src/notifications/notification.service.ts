import { Injectable, Logger, OnModuleInit, Inject, Optional } from "@nestjs/common";
import { OnEvent } from "@nestjs/event-emitter";
import { Cron, CronExpression } from "@nestjs/schedule";

import { NotificationPreferencesRepository } from "./notification-preferences.repository";
import { NotificationLogRepository } from "./notification-log.repository";
import { NotificationRateLimiter } from "./notification-rate-limiter";
import {
  NOTIFICATION_PROVIDERS,
  INotificationProvider,
} from "./providers/notification-provider.interface";

import type {
  NotificationPayload,
  NotificationPreference,
  EscrowDepositedPayload,
  EscrowWithdrawnPayload,
  EscrowRefundedPayload,
  PaymentReceivedPayload,
  UsernameClaimedPayload,
  AutoReconciliationSucceededNotificationPayload,
  PaymentLinkExpiredPayload,
  ExportCompletedPayload,
  ExportFailedPayload,
} from "./types/notification.types";

import {
  NotificationEvent,
  PaymentReceivedEvent,
  UsernameClaimedEvent,
  AutoReconciliationSucceededEvent,
} from "../events/notification.events";

import type {
  EscrowDepositedEvent,
  EscrowWithdrawnEvent,
  EscrowRefundedEvent,
} from "../ingestion/types/contract-event.types";

import { JobQueueService } from "../job-queue/job-queue.service";
import { JobType } from "../job-queue/types";
import type { WebhookDeliveryPayload } from "../job-queue/types/job-payloads.types";

import { InAppNotificationRepository } from "./in-app-notification.repository";
import { TemplateVersionService } from "./template-versioning/template-version.service";

const MAX_ATTEMPTS = 3;

/** Outcome of a single channel delivery attempt. */
export interface ChannelDeliveryResult {
  /** Whether the notification reached (or was already delivered to) the channel. */
  ok: boolean;
  /** Populated when the delivery did not succeed. */
  error?: string;
  /** Provider message id when available. */
  messageId?: string;
}

/** Outcome of an export email delivery request. */
export interface ExportEmailDeliveryResult {
  delivered: boolean;
  templateVersionId?: string;
  error?: string;
}

@Injectable()
export class NotificationService implements OnModuleInit {
  private readonly logger = new Logger(NotificationService.name);
  readonly rateLimiter = new NotificationRateLimiter(10, 60 * 60 * 1_000);
  private readonly providerMap = new Map<string, INotificationProvider>();

  constructor(
    @Inject(NOTIFICATION_PROVIDERS)
    private readonly providers: INotificationProvider[],
    private readonly prefsRepo: NotificationPreferencesRepository,
    private readonly inAppRepo: InAppNotificationRepository,
    private readonly templateVersionService: TemplateVersionService,
    private readonly logRepo: NotificationLogRepository,
    @Optional() private readonly jobQueueService?: JobQueueService,
  ) {}

  onModuleInit(): void {
    for (const p of this.providers) {
      this.providerMap.set(p.channel, p);
    }

    this.logger.log(
      "NotificationService ready. Channels: [" +
        [...this.providerMap.keys()].join(", ") +
        "]",
    );
  }

  // ---------------------------------------------------------------------------
  // EVENT HANDLERS (UNCHANGED)
  // ---------------------------------------------------------------------------

  @OnEvent("stellar.EscrowDeposited", { async: true })
  async onEscrowDeposited(event: EscrowDepositedEvent): Promise<void> {
    const payload: EscrowDepositedPayload = {
      eventType: "EscrowDeposited",
      eventId: event.pagingToken,
      recipientPublicKey: event.owner,
      title: "Escrow Deposit Confirmed",
      body:
        "Your escrow of " +
        this.formatAmount(event.amount) +
        " has been deposited.",
      occurredAt: new Date(
        Number(event.contractTimestamp) * 1000,
      ).toISOString(),
      amountStroops: event.amount,
      commitment: event.commitment,
      token: event.token,
      metadata: { commitment: event.commitment, token: event.token },
    };

    await this.dispatch(payload);
  }

  @OnEvent("stellar.EscrowWithdrawn", { async: true })
  async onEscrowWithdrawn(event: EscrowWithdrawnEvent): Promise<void> {
    const payload: EscrowWithdrawnPayload = {
      eventType: "EscrowWithdrawn",
      eventId: event.pagingToken,
      recipientPublicKey: event.owner,
      title: "Escrow Withdrawn",
      body:
        "Your escrow of " +
        this.formatAmount(event.amount) +
        " has been released.",
      occurredAt: new Date(
        Number(event.contractTimestamp) * 1000,
      ).toISOString(),
      amountStroops: event.amount,
      commitment: event.commitment,
      token: event.token,
      metadata: { commitment: event.commitment, token: event.token },
    };

    await this.dispatch(payload);
  }

  @OnEvent("stellar.EscrowRefunded", { async: true })
  async onEscrowRefunded(event: EscrowRefundedEvent): Promise<void> {
    const payload: EscrowRefundedPayload = {
      eventType: "EscrowRefunded",
      eventId: event.pagingToken,
      recipientPublicKey: event.owner,
      title: "Escrow Refunded",
      body:
        "Your escrow of " +
        this.formatAmount(event.amount) +
        " has been refunded.",
      occurredAt: new Date(
        Number(event.contractTimestamp) * 1000,
      ).toISOString(),
      amountStroops: event.amount,
      commitment: event.commitment,
      token: event.token,
      metadata: { commitment: event.commitment, token: event.token },
    };

    await this.dispatch(payload);
  }

  @OnEvent(NotificationEvent.PaymentReceived, { async: true })
  async onPaymentReceived(event: PaymentReceivedEvent): Promise<void> {
    const amountStroops = BigInt(event.amount);

    const payload: PaymentReceivedPayload = {
      eventType: "payment.received",
      eventId: event.txHash,
      recipientPublicKey: event.recipientPublicKey,
      title: "Payment Received",
      body:
        "You received " +
        this.formatAmount(amountStroops) +
        " from " +
        event.sender.slice(0, 8) +
        "...",
      occurredAt: new Date().toISOString(),
      amountStroops,
      txHash: event.txHash,
      sender: event.sender,
      metadata: { txHash: event.txHash, sender: event.sender },
    };

    await this.dispatch(payload);
  }

  @OnEvent("auto_reconciliation.succeeded", { async: true })
  async onAutoReconciliationSucceeded(event: AutoReconciliationSucceededEvent): Promise<void> {
    const payload: AutoReconciliationSucceededNotificationPayload = {
      eventType: "auto_reconciliation.succeeded",
      eventId: event.txHash,
      recipientPublicKey: event.ownerPublicKey,
      title: "Payment Link Fulfilled",
      body:
        "Your payment link for " +
        event.amount +
        " " +
        event.assetCode +
        " has been automatically matched and marked as paid.",
      occurredAt: event.matchedAt,
      linkId: event.linkId,
      txHash: event.txHash,
      assetCode: event.assetCode,
      confidence: event.confidence,
      metadata: {
        linkId: event.linkId,
        txHash: event.txHash,
        confidence: event.confidence,
      },
    };
    await this.dispatch(payload);
  }

  @OnEvent("payment.link.expired", { async: true })
  async onPaymentLinkExpired(event: { linkId: string; expiresAt?: string | null; ownerPublicKey?: string | null }): Promise<void> {
    if (!event.ownerPublicKey) return;
    const payload: PaymentLinkExpiredPayload = {
      eventType: 'payment.link.expired',
      eventId: `link:${event.linkId}:expired:${event.expiresAt ?? ''}`,
      recipientPublicKey: event.ownerPublicKey,
      title: 'Payment Link Expired',
      body: 'A payment link you created has expired.',
      occurredAt: new Date().toISOString(),
      linkId: event.linkId,
      expiredAt: event.expiresAt ?? null,
      metadata: { linkId: event.linkId, expiredAt: event.expiresAt ?? null },
    };

    await this.dispatch(payload);
  }

  @OnEvent(NotificationEvent.UsernameClaimed, { async: true })
  async onUsernameClaimed(event: UsernameClaimedEvent): Promise<void> {
    const payload: UsernameClaimedPayload = {
      eventType: "username.claimed",
      eventId: "username:" + event.username,
      recipientPublicKey: event.publicKey,
      title: "Username Registered",
      body:
        "Your username @" +
        event.username +
        " has been successfully registered.",
      occurredAt: new Date().toISOString(),
      username: event.username,
    };

    await this.dispatch(payload);
  }

  // ---------------------------------------------------------------------------
  // CORE DISPATCH (UPDATED WITH TEMPLATE)
  // ---------------------------------------------------------------------------

  async dispatch(payload: NotificationPayload): Promise<void> {
    let preferences: NotificationPreference[];

    try {
      preferences = await this.prefsRepo.getEnabledPreferences(
        payload.recipientPublicKey,
      );
    } catch (err) {
      this.logger.error(
        "Failed to load preferences for " +
          payload.recipientPublicKey +
          ": " +
          String(err),
      );
      return;
    }

    if (preferences.length === 0) return;

    // Use versioned template service to render active template and get its ID
    const renderedTemplate = await this.templateVersionService.renderActiveTemplateForEventType(
      payload.eventType, 
      payload as unknown as Record<string, unknown>
    );

    const renderedPayload: NotificationPayload = {
      ...payload,
      title: renderedTemplate ? renderedTemplate.title : payload.title,
      body: renderedTemplate ? renderedTemplate.body : payload.body,
    };

    // Store template version ID for persistence in notification logs
    const templateVersionId = renderedTemplate?.templateVersionId;

    const filtered = preferences.filter((pref) =>
      this.matchesPreference(renderedPayload, pref),
    );

    await Promise.allSettled(
      filtered.map((pref) => this.sendToChannel(pref, renderedPayload, templateVersionId)),
    );
  }

  // ---------------------------------------------------------------------------
  // CHANNEL DELIVERY (UPDATED WITH IN-APP)
  // ---------------------------------------------------------------------------

  async sendToChannel(
    pref: NotificationPreference,
    payload: NotificationPayload,
    templateVersionId?: string,
  ): Promise<ChannelDeliveryResult> {
    const { publicKey, channel } = pref;
    const { eventType, eventId } = payload;

    const alreadySent = await this.logRepo.isAlreadySent(
      publicKey,
      channel,
      eventType,
      eventId,
    );

    if (alreadySent) return { ok: true };

    if (!this.rateLimiter.allow(publicKey, channel)) {
      return {
        ok: false,
        error: `Rate limit exceeded for ${publicKey} on channel ${channel}`,
      };
    }

    // ✅ IN-APP CHANNEL
    if (channel === "in_app") {
      await this.logRepo.createPending(publicKey, channel, eventType, eventId, templateVersionId);
      await this.logRepo.createPending(publicKey, channel, eventType, eventId, payload.previewScope);

      try {
        await this.inAppRepo.create({
          publicKey,
          eventType,
          eventId,
          title: payload.title,
          body: payload.body,
          metadata: payload.metadata,
          previewScope: payload.previewScope,
        });

        await this.logRepo.markSent(publicKey, channel, eventType, eventId);
        return { ok: true };
      } catch (err) {
        const message = (err as Error).message;
        await this.logRepo.markFailed(
          publicKey,
          channel,
          eventType,
          eventId,
          message,
        );
        return { ok: false, error: message };
      }
    }

    // webhook async handling
    if (channel === "webhook" && this.jobQueueService) {
      await this.enqueueWebhookJob(pref, payload, templateVersionId);
      return { ok: true };
    }

    const provider = this.providerMap.get(channel);
    if (!provider) {
      return { ok: false, error: `No provider registered for channel ${channel}` };
    }

    await this.logRepo.createPending(publicKey, channel, eventType, eventId, templateVersionId);
    await this.logRepo.createPending(publicKey, channel, eventType, eventId, payload.previewScope);

    try {
      const result = await provider.send(pref, payload);

      await this.logRepo.markSent(
        publicKey,
        channel,
        eventType,
        eventId,
        result.messageId,
        result.httpStatus,
        result.responseBody,
      );

      return { ok: true, messageId: result.messageId };
    } catch (err) {
      const message = (err as Error).message;
      await this.logRepo.markFailed(
        publicKey,
        channel,
        eventType,
        eventId,
        message,
      );
      return { ok: false, error: message };
    }
  }

  // ---------------------------------------------------------------------------
  // EXPORT EMAIL DELIVERY (BE-101)
  // ---------------------------------------------------------------------------

  /**
   * Deliver a completed-export notification email.
   *
   * Routes through the existing notifications pipeline: the recipient's enabled
   * email preference is resolved, the active versioned template for
   * `export.completed` is rendered, and the configured email provider sends it.
   *
   * Unlike {@link dispatch}, this returns the delivery outcome so callers
   * (e.g. the export generation job handler) can surface failures instead of
   * having them swallowed.
   */
  async deliverExportEmail(
    payload: ExportCompletedPayload,
  ): Promise<ExportEmailDeliveryResult> {
    let emailPref: NotificationPreference | undefined;

    try {
      const preferences = await this.prefsRepo.getEnabledPreferences(
        payload.recipientPublicKey,
      );
      emailPref = preferences.find((pref) => pref.channel === "email");
    } catch (err) {
      const message = `Failed to load notification preferences: ${(err as Error).message}`;
      this.logger.error(message);
      return { delivered: false, error: message };
    }

    if (!emailPref || !emailPref.email) {
      return {
        delivered: false,
        error: `No enabled email channel preference with an email address found for ${payload.recipientPublicKey}`,
      };
    }

    const renderedTemplate =
      await this.templateVersionService.renderActiveTemplateForEventType(
        payload.eventType,
        payload as unknown as Record<string, unknown>,
      );

    const templatedPayload: ExportCompletedPayload = renderedTemplate
      ? { ...payload, title: renderedTemplate.title, body: renderedTemplate.body }
      : payload;

    const result = await this.sendToChannel(
      emailPref,
      templatedPayload,
      renderedTemplate?.templateVersionId,
    );

    return {
      delivered: result.ok,
      templateVersionId: renderedTemplate?.templateVersionId,
      error: result.error,
    };
  }

  /**
   * Notify the requesting user that their export job has permanently failed.
   *
   * Dispatches an `export.failed` notification through the standard
   * multi-channel pipeline so user preferences (email, in-app, etc.) are
   * respected.  The `failureReason` field is sanitised by the caller and must
   * never contain raw stack traces or internal error messages.
   *
   * @param userId - Stellar public key of the user who requested the export.
   * @param jobId - ID of the failed export generation job.
   * @param exportType - The type of data (transactions, links, payments).
   * @param format - The requested output format (csv or json).
   * @param failureReason - A user-safe description of why the export failed.
   */
  async notifyExportFailed(
    userId: string,
    jobId: string,
    exportType: string,
    format: string,
    failureReason: string,
  ): Promise<void> {
    const payload: ExportFailedPayload = {
      eventType: "export.failed",
      eventId: `export-failed:${jobId}`,
      recipientPublicKey: userId,
      title: `Your ${exportType} export failed`,
      body: `We were unable to generate your ${format.toUpperCase()} export. ${failureReason}`,
      occurredAt: new Date().toISOString(),
      exportType,
      format,
      jobId,
      failureReason,
      metadata: { jobId, exportType, format, failureReason },
    };

    await this.dispatch(payload);
  }

  // ---------------------------------------------------------------------------
  // RETRY (UNCHANGED)
  // ---------------------------------------------------------------------------

  @Cron(CronExpression.EVERY_30_MINUTES)
  async retryFailedNotifications(): Promise<void> {
    const retries = await this.logRepo.getPendingRetries(MAX_ATTEMPTS);

    for (const entry of retries) {
      try {
        const prefs = await this.prefsRepo.getEnabledPreferences(
          entry.publicKey,
        );
        const pref = prefs.find((p) => p.channel === entry.channel);
        if (!pref) continue;

        const synthetic = {
          eventType: entry.eventType,
          eventId: entry.eventId,
          recipientPublicKey: entry.publicKey,
          title: "Retry: " + entry.eventType,
          body: "Retry notification for event " + entry.eventId,
          occurredAt: new Date().toISOString(),
        } as NotificationPayload;

        await this.sendToChannel(pref, synthetic);
      } catch {}
    }
  }

  // ---------------------------------------------------------------------------
  // HELPERS
  // ---------------------------------------------------------------------------

  private matchesPreference(
    payload: NotificationPayload,
    pref: NotificationPreference,
  ): boolean {
    if (pref.events !== null && !pref.events.includes(payload.eventType)) {
      return false;
    }

    if (pref.minAmountStroops > 0n && payload.amountStroops !== undefined) {
      if (payload.amountStroops < pref.minAmountStroops) {
        return false;
      }
    }

    return true;
  }

  private formatAmount(stroops: bigint): string {
    const xlm = Number(stroops) / 10_000_000;
    return xlm.toFixed(7) + " XLM";
  }

  private async enqueueWebhookJob(
    pref: NotificationPreference,
    payload: NotificationPayload,
    templateVersionId?: string,
  ): Promise<void> {
    const { publicKey, webhookUrl } = pref;
    const { eventType, eventId } = payload;

    if (!webhookUrl) return;

    await this.logRepo.createPending(publicKey, "webhook", eventType, eventId, templateVersionId);
    await this.logRepo.createPending(publicKey, "webhook", eventType, eventId, payload.previewScope);

    const jobPayload: WebhookDeliveryPayload = {
      recipientPublicKey: publicKey,
      webhookUrl,
      eventType,
      eventId,
      previewScope: payload.previewScope,
      correlationId: payload.correlationId,
      payload: {
        title: payload.title,
        body: payload.body,
        occurredAt: payload.occurredAt,
        amountStroops: payload.amountStroops?.toString(),
        metadata: payload.metadata,
      },
    };

    await this.jobQueueService!.enqueue(
      JobType.WEBHOOK_DELIVERY,
      jobPayload,
    );
  }
}