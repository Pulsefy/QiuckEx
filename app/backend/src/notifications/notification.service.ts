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
import { TemplateService } from "./template.service";

const MAX_ATTEMPTS = 3;

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
    private readonly templateService: TemplateService,
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

    const template = this.templateService.getTemplate(payload.eventType);

    const renderedPayload: NotificationPayload = {
      ...payload,
      title: template
        ? this.templateService.render(template.title, payload as unknown as Record<string, unknown>)
        : payload.title,
      body: template
        ? this.templateService.render(template.body, payload as unknown as Record<string, unknown>)
        : payload.body,
    };

    const filtered = preferences.filter((pref) =>
      this.matchesPreference(renderedPayload, pref),
    );

    await Promise.allSettled(
      filtered.map((pref) => this.sendToChannel(pref, renderedPayload)),
    );
  }

  // ---------------------------------------------------------------------------
  // CHANNEL DELIVERY (UPDATED WITH IN-APP)
  // ---------------------------------------------------------------------------

  async sendToChannel(
    pref: NotificationPreference,
    payload: NotificationPayload,
  ): Promise<void> {
    const { publicKey, channel } = pref;
    const { eventType, eventId } = payload;

    const alreadySent = await this.logRepo.isAlreadySent(
      publicKey,
      channel,
      eventType,
      eventId,
    );

    if (alreadySent) return;

    if (!this.rateLimiter.allow(publicKey, channel)) return;

    // ✅ IN-APP CHANNEL
    if (channel === "in_app") {
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
      } catch (err) {
        await this.logRepo.markFailed(
          publicKey,
          channel,
          eventType,
          eventId,
          (err as Error).message,
        );
      }

      return;
    }

    // webhook async handling
    if (channel === "webhook" && this.jobQueueService) {
      await this.enqueueWebhookJob(pref, payload);
      return;
    }

    const provider = this.providerMap.get(channel);
    if (!provider) return;

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
    } catch (err) {
      await this.logRepo.markFailed(
        publicKey,
        channel,
        eventType,
        eventId,
        (err as Error).message,
      );
    }
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
  ): Promise<void> {
    const { publicKey, webhookUrl } = pref;
    const { eventType, eventId } = payload;

    if (!webhookUrl) return;

    await this.logRepo.createPending(publicKey, "webhook", eventType, eventId, payload.previewScope);

    const jobPayload: WebhookDeliveryPayload = {
      recipientPublicKey: publicKey,
      webhookUrl,
      eventType,
      eventId,
      previewScope: payload.previewScope,
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