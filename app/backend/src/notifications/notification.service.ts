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
} from "./types/notification.types";
import {
  NotificationEvent,
  PaymentReceivedEvent,
  UsernameClaimedEvent,
} from "../events/notification.events";
import type {
  EscrowDepositedEvent,
  EscrowWithdrawnEvent,
  EscrowRefundedEvent,
} from "../ingestion/types/contract-event.types";
import { JobQueueService } from "../job-queue/job-queue.service";
import { JobType } from "../job-queue/types";
import type { WebhookDeliveryPayload } from "../job-queue/types/job-payloads.types";

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

    const filtered = preferences.filter((pref) =>
      this.matchesPreference(payload, pref),
    );

    await Promise.allSettled(
      filtered.map((pref) => this.sendToChannel(pref, payload)),
    );
  }

  @Cron(CronExpression.EVERY_30_MINUTES)
  async retryFailedNotifications(): Promise<void> {
    const retries = await this.logRepo.getPendingRetries(MAX_ATTEMPTS);
    if (retries.length === 0) return;

    this.logger.log("Retrying " + retries.length + " failed notifications");

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
      } catch (err) {
        this.logger.warn(
          "Retry failed for " + entry.eventId + ": " + String(err),
        );
      }
    }
  }

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

    if (alreadySent) {
      this.logger.debug(
        "Already sent " +
          eventType +
          "/" +
          eventId +
          " via " +
          channel +
          " - skipping",
      );
      return;
    }

    if (!this.rateLimiter.allow(publicKey, channel)) {
      this.logger.warn(
        "Rate limit hit for " +
          publicKey +
          "/" +
          channel +
          " - dropping " +
          eventType +
          "/" +
          eventId,
      );
      return;
    }

    // Special handling for webhook channel: enqueue job instead of direct delivery
    if (channel === "webhook" && this.jobQueueService) {
      await this.enqueueWebhookJob(pref, payload);
      return;
    }

    const provider = this.providerMap.get(channel);

    if (!provider) {
      this.logger.warn("No provider registered for channel " + channel);
      return;
    }

    await this.logRepo.createPending(publicKey, channel, eventType, eventId);

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

      this.logger.log(
        "[" +
          channel +
          "] Sent " +
          eventType +
          " to " +
          publicKey.slice(0, 8) +
          "...",
      );
    } catch (err) {
      const msg = (err as Error).message;

      await this.logRepo.markFailed(
        publicKey,
        channel,
        eventType,
        eventId,
        msg,
      );

      this.logger.error(
        "[" +
          channel +
          "] Failed " +
          eventType +
          " to " +
          publicKey.slice(0, 8) +
          "...: " +
          msg,
      );
    }
  }

  private formatAmount(stroops: bigint): string {
    const xlm = Number(stroops) / 10_000_000;
    return xlm.toFixed(7) + " XLM";
  }

  /**
   * Enqueue a webhook delivery job instead of sending directly
   * 
   * Creates a WebhookDeliveryPayload and enqueues it to the job queue.
   * The job will be picked up by the JobExecutor and handled by WebhookDeliveryHandler.
   * 
   * **Validates: Requirement 7.2**
   */
  private async enqueueWebhookJob(
    pref: NotificationPreference,
    payload: NotificationPayload,
  ): Promise<void> {
    const { publicKey, webhookUrl, webhookSecret } = pref;
    const { eventType, eventId } = payload;

    if (!webhookUrl) {
      this.logger.warn(
        "No webhook URL configured for " + publicKey + " - skipping",
      );
      return;
    }

    // Create pending log entry (will be updated by WebhookDeliveryHandler)
    await this.logRepo.createPending(publicKey, "webhook", eventType, eventId);

    try {
      // Build WebhookDeliveryPayload
      const jobPayload: WebhookDeliveryPayload = {
        recipientPublicKey: publicKey,
        webhookUrl,
        eventType,
        eventId,
        payload: {
          title: payload.title,
          body: payload.body,
          occurredAt: payload.occurredAt,
          amountStroops: payload.amountStroops?.toString(),
          metadata: payload.metadata,
        },
      };

      // Enqueue webhook delivery job
      const jobId = await this.jobQueueService!.enqueue(
        JobType.WEBHOOK_DELIVERY,
        jobPayload,
      );

      this.logger.log(
        "[webhook] Enqueued job " +
          jobId +
          " for " +
          eventType +
          " to " +
          publicKey.slice(0, 8) +
          "...",
      );
    } catch (err) {
      const msg = (err as Error).message;

      // Mark as failed if enqueue fails
      await this.logRepo.markFailed(
        publicKey,
        "webhook",
        eventType,
        eventId,
        "Failed to enqueue webhook job: " + msg,
      );

      this.logger.error(
        "[webhook] Failed to enqueue job for " +
          eventType +
          " to " +
          publicKey.slice(0, 8) +
          "...: " +
          msg,
      );
    }
  }
}