import { randomUUID } from "crypto";

/**
 * Lifecycle of an outbox row.
 * - `pending`: written alongside the originating state change, not yet delivered.
 * - `dispatched`: delivered at-least-once to consumers (idempotent on their side).
 * - `failed`: attempts exhausted; routed to a dead-letter state for inspection.
 */
export type OutboxStatus = "pending" | "dispatched" | "failed";

export interface OutboxMessage {
  id: string;
  eventId: string;
  aggregateType: string;
  aggregateId: string;
  eventType: string;
  payload: Record<string, unknown>;
  status: OutboxStatus;
  attempts: number;
  nextAttemptAt: string;
  lastError: string | null;
  createdAt: string;
  dispatchedAt: string | null;
}

export interface OutboxStageInput {
  /** Deterministic, content-derived id used by consumers for deduplication. */
  eventId: string;
  aggregateType: string;
  aggregateId: string;
  eventType: string;
  payload: Record<string, unknown>;
  /** Delay delivery until this time (used for scheduled/retry backoff). */
  deliverAfter?: Date;
}

/**
 * Build a deterministic event id that is stable for the same logical event.
 *
 * The id MUST be derived from the domain state rather than from randomness so
 * that consumers (webhooks, notification log, replay limiter, indexer) can
 * deduplicate redeliveries. The scheme mirrors the existing deterministic ids
 * already used across the notification pipeline, e.g.
 *   `username:alice` for a username claim,
 *   `<txHash>` for a payment,
 *   `link:<id>:expired:<ts>` for an expired link.
 */
export function buildDeterministicEventId(eventType: string, seed: string): string {
  return `${eventType}:${seed}`;
}

export function createOutboxId(): string {
  return randomUUID();
}
