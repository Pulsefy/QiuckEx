import { Injectable, Logger, OnModuleDestroy, OnModuleInit } from "@nestjs/common";
import { EventEmitter2 } from "@nestjs/event-emitter";

import { MetricsService } from "../../metrics/metrics.service";
import { OutboxRepository } from "./outbox.repository";
import { OutboxMessage } from "./outbox.types";

export const OUTBOX_MAX_ATTEMPTS = 25;
export const OUTBOX_BATCH_SIZE = 100;
export const OUTBOX_POLL_INTERVAL_MS = 1000;
export const OUTBOX_BASE_BACKOFF_MS = 1000;
export const OUTBOX_MAX_BACKOFF_MS = 60_000;

export type OutboxDispatchOutcome = "success" | "retry" | "dead";

/**
 * Polls the outbox table and re-publishes pending events through the process
 * event bus. Delivery is at-least-once: a row is only marked `dispatched` after
 * the publish call returns, so a crash between the originating commit and
 * dispatch leaves the row `pending` and it is redelivered on the next tick.
 * Consumers deduplicate using the deterministic `eventId`.
 */
@Injectable()
export class OutboxDispatcher implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(OutboxDispatcher.name);
  private timer?: ReturnType<typeof setTimeout>;
  private running = false;
  private started = false;

  constructor(
    private readonly repository: OutboxRepository,
    private readonly eventEmitter: EventEmitter2,
    private readonly metrics: MetricsService,
  ) {}

  onModuleInit(): void {
    this.start();
  }

  onModuleDestroy(): void {
    this.stop();
  }

  start(): void {
    if (this.started) return;
    this.started = true;
    this.scheduleNext();
  }

  stop(): void {
    this.started = false;
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = undefined;
    }
  }

  private scheduleNext(): void {
    if (!this.started) return;
    this.timer = setTimeout(() => {
      void this.tick().finally(() => this.scheduleNext());
    }, OUTBOX_POLL_INTERVAL_MS);
    // Don't keep the process alive solely for the poll loop.
    this.timer.unref?.();
  }

  /** Run one polling cycle. Safe to invoke manually from tests. */
  async tick(): Promise<number> {
    if (this.running) return 0;
    this.running = true;
    try {
      return await this.dispatchBatch();
    } finally {
      this.running = false;
    }
  }

  async dispatchBatch(): Promise<number> {
    const now = new Date();
    const pending = await this.repository.findPending(
      OUTBOX_BATCH_SIZE,
      OUTBOX_MAX_ATTEMPTS,
      now,
    );

    let dispatched = 0;
    for (const message of pending) {
      const ok = await this.dispatchOne(message, now);
      if (ok) dispatched += 1;
    }

    try {
      const depth = await this.repository.getDepth(now);
      this.metrics.setOutboxDepth(depth);

      const lag = await this.repository.getLagSeconds(now);
      if (lag !== null) {
        this.metrics.setOutboxDispatchLagSeconds(lag);
      }
    } catch (error) {
      this.logger.warn(`metrics update failed: ${(error as Error).message}`);
    }

    return dispatched;
  }

  private async dispatchOne(
    message: OutboxMessage,
    now: Date,
  ): Promise<boolean> {
    try {
      this.eventEmitter.emit(message.eventType, message.payload);
      await this.repository.markDispatched(message.id, now);
      this.recordOutcome(message.eventType, "success");
      return true;
    } catch (error) {
      const attempts = message.attempts + 1;
      const deadLetter = attempts >= OUTBOX_MAX_ATTEMPTS;
      const backoff = this.backoffFor(attempts);
      await this.repository.recordAttempt(
        message.id,
        (error as Error).message ?? "unknown error",
        attempts,
        deadLetter,
        new Date(now.getTime() + backoff),
      );
      this.recordOutcome(message.eventType, deadLetter ? "dead" : "retry");
      this.logger.error(
        `Outbox dispatch failed for ${message.eventType} (${message.id}, attempt ${attempts}): ${(error as Error).message}`,
      );
      return false;
    }
  }

  private backoffFor(attempts: number): number {
    const delay = OUTBOX_BASE_BACKOFF_MS * 2 ** (attempts - 1);
    return Math.min(delay, OUTBOX_MAX_BACKOFF_MS);
  }

  private recordOutcome(
    eventType: string,
    outcome: OutboxDispatchOutcome,
  ): void {
    try {
      this.metrics.recordOutboxDispatch(eventType, outcome);
    } catch {
      /* metrics are best-effort */
    }
  }
}
