import { Injectable, Logger } from "@nestjs/common";
import { SupabaseClient } from "@supabase/supabase-js";

import { SupabaseService } from "../../supabase/supabase.service";
import { SupabaseError } from "../../supabase/supabase.errors";
import {
  OutboxMessage,
  OutboxStageInput,
  OutboxStatus,
  createOutboxId,
} from "./outbox.types";

interface OutboxRow {
  id: string;
  event_id: string;
  aggregate_type: string;
  aggregate_id: string;
  event_type: string;
  payload: Record<string, unknown>;
  status: OutboxStatus;
  attempts: number;
  next_attempt_at: string;
  last_error: string | null;
  created_at: string;
  dispatched_at: string | null;
}

function mapRow(row: OutboxRow): OutboxMessage {
  return {
    id: row.id,
    eventId: row.event_id,
    aggregateType: row.aggregate_type,
    aggregateId: row.aggregate_id,
    eventType: row.event_type,
    payload: row.payload ?? {},
    status: row.status,
    attempts: row.attempts,
    nextAttemptAt: row.next_attempt_at,
    lastError: row.last_error,
    createdAt: row.created_at,
    dispatchedAt: row.dispatched_at,
  };
}

/**
 * Durable store for domain events. Rows are written in the same database
 * transaction as the originating state change (see the `claim_username_with_outbox`
 * Postgres function and the repository helpers that wrap domain writes together
 * with `stage`) and later picked up by {@link OutboxDispatcher}.
 */
@Injectable()
export class OutboxRepository {
  private readonly logger = new Logger(OutboxRepository.name);
  private readonly client: SupabaseClient;

  constructor(supabase: SupabaseService) {
    this.client = supabase.getClient();
  }

  /**
   * Append a single event to the outbox. MUST be called from within the same
   * transaction as the originating state change so that a crash between the
   * state write and dispatch cannot lose the event.
   */
  async stage(input: OutboxStageInput): Promise<OutboxMessage> {
    const now = new Date();
    const deliverAfter = input.deliverAfter ?? now;
    const row: OutboxRow = {
      id: createOutboxId(),
      event_id: input.eventId,
      aggregate_type: input.aggregateType,
      aggregate_id: input.aggregateId,
      event_type: input.eventType,
      payload: input.payload,
      status: "pending",
      attempts: 0,
      next_attempt_at: deliverAfter.toISOString(),
      last_error: null,
      created_at: now.toISOString(),
      dispatched_at: null,
    };

    const { data, error } = await this.client
      .from("outbox")
      .insert(row)
      .select()
      .single();

    if (error) {
      throw new SupabaseError(
        `Failed to stage outbox event ${input.eventType}: ${error.message}`,
        error.code,
        error,
      );
    }

    return mapRow(data as OutboxRow);
  }

  /**
   * Fetch dispatchable messages: still pending and not past their retry cap,
   * whose backoff window has elapsed. Ordered oldest-first for FIFO delivery.
   */
  async findPending(
    limit: number,
    maxAttempts: number,
    now: Date = new Date(),
  ): Promise<OutboxMessage[]> {
    const { data, error } = await this.client
      .from("outbox")
      .select("*")
      .eq("status", "pending")
      .lt("attempts", maxAttempts)
      .lte("next_attempt_at", now.toISOString())
      .order("created_at", { ascending: true })
      .limit(limit);

    if (error) {
      throw new SupabaseError(
        `Failed to read pending outbox events: ${error.message}`,
        error.code,
        error,
      );
    }

    return ((data as OutboxRow[]) ?? []).map(mapRow);
  }

  async markDispatched(id: string, now: Date = new Date()): Promise<void> {
    const { error } = await this.client
      .from("outbox")
      .update({ status: "dispatched", dispatched_at: now.toISOString() })
      .eq("id", id);

    if (error) {
      throw new SupabaseError(
        `Failed to mark outbox event ${id} dispatched: ${error.message}`,
        error.code,
        error,
      );
    }
  }

  /**
   * Record a failed dispatch attempt, bumping the attempt counter and applying
   * the next retry delay. Once attempts reach the cap the row is moved to the
   * `failed` dead-letter state and stop being retried.
   */
  async recordAttempt(
    id: string,
    errorMessage: string,
    attempts: number,
    deadLetter: boolean,
    nextAttemptAt: Date,
  ): Promise<void> {
    const { error } = await this.client
      .from("outbox")
      .update({
        attempts,
        last_error: errorMessage,
        status: deadLetter ? "failed" : "pending",
        next_attempt_at: nextAttemptAt.toISOString(),
      })
      .eq("id", id);

    if (error) {
      throw new SupabaseError(
        `Failed to record outbox attempt for ${id}: ${error.message}`,
        error.code,
        error,
      );
    }
  }

  /** Number of events currently due for dispatch. */
  async getDepth(now: Date = new Date()): Promise<number> {
    const { count, error } = await this.client
      .from("outbox")
      .select("*", { count: "exact", head: true })
      .eq("status", "pending")
      .lte("next_attempt_at", now.toISOString());

    if (error) {
      this.logger.warn(`getDepth failed: ${error.message}`);
      return 0;
    }
    return count ?? 0;
  }

  /**
   * Seconds between now and the oldest pending event's creation — i.e. how long
   * the head of the queue has been waiting for dispatch. Null when empty.
   */
  async getLagSeconds(now: Date = new Date()): Promise<number | null> {
    const { data, error } = await this.client
      .from("outbox")
      .select("created_at")
      .eq("status", "pending")
      .lte("next_attempt_at", now.toISOString())
      .order("created_at", { ascending: true })
      .limit(1);

    if (error || !data || data.length === 0) {
      return null;
    }
    const ageMs = now.getTime() - new Date((data[0] as { created_at: string }).created_at).getTime();
    return Math.max(0, Math.round(ageMs / 1000));
  }
}
