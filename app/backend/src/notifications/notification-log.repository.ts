import { Injectable, Logger } from "@nestjs/common";
import { SupabaseService } from "../supabase/supabase.service";
import {
  NotificationChannel,
  NotificationEventType,
} from "./types/notification.types";

@Injectable()
export class NotificationLogRepository {
  private readonly logger = new Logger(NotificationLogRepository.name);

  constructor(private readonly supabase: SupabaseService) {}

  /**
   * Create a pending log entry.
   * Uses ON CONFLICT DO NOTHING so duplicate events don't create extra rows.
   * Returns the existing or newly created row id.
   */
  async createPending(
    publicKey: string,
    channel: NotificationChannel,
    eventType: NotificationEventType,
    eventId: string,
  ): Promise<string | null> {
    const { data, error } = await this.supabase
      .getClient()
      .from("notification_log")
      .upsert(
        {
          public_key: publicKey,
          channel,
          event_type: eventType,
          event_id: eventId,
          status: "pending",
          attempts: 0,
        },
        {
          onConflict: "public_key,channel,event_id,event_type",
          ignoreDuplicates: true,
        },
      )
      .select("id")
      .maybeSingle();

    if (error) {
      this.logger.error(`Failed to create pending log: ${error.message}`);
      return null;
    }

    return data?.id ?? null;
  }

  /** Mark a delivery as sent. */
  async markSent(
    publicKey: string,
    channel: NotificationChannel,
    eventType: NotificationEventType,
    eventId: string,
    providerMessageId?: string,
  ): Promise<void> {
    const { error } = await this.supabase
      .getClient()
      .from("notification_log")
      .update({
        status: "sent",
        provider_message_id: providerMessageId ?? null,
        last_error: null,
      })
      .eq("public_key", publicKey)
      .eq("channel", channel)
      .eq("event_type", eventType)
      .eq("event_id", eventId);

    if (error) {
      this.logger.warn(`Failed to mark notification sent: ${error.message}`);
    }
  }

  /** Mark a delivery as failed, recording the error and incrementing attempts. */
  async markFailed(
    publicKey: string,
    channel: NotificationChannel,
    eventType: NotificationEventType,
    eventId: string,
    errorMessage: string,
  ): Promise<void> {
    // Increment attempts via RPC or read-modify-write (simple approach)
    const client = this.supabase.getClient();

    // Read current attempt count
    const { data } = await client
      .from("notification_log")
      .select("attempts")
      .eq("public_key", publicKey)
      .eq("channel", channel)
      .eq("event_type", eventType)
      .eq("event_id", eventId)
      .maybeSingle();

    const attempts = (data?.attempts ?? 0) + 1;

    const { error } = await client
      .from("notification_log")
      .update({ status: "failed", last_error: errorMessage, attempts })
      .eq("public_key", publicKey)
      .eq("channel", channel)
      .eq("event_type", eventType)
      .eq("event_id", eventId);

    if (error) {
      this.logger.warn(`Failed to mark notification failed: ${error.message}`);
    }
  }

  /** Return failed entries eligible for retry (status=failed, attempts < maxAttempts). */
  async getPendingRetries(maxAttempts: number): Promise<
    Array<{
      publicKey: string;
      channel: NotificationChannel;
      eventType: NotificationEventType;
      eventId: string;
      attempts: number;
    }>
  > {
    const { data, error } = await this.supabase
      .getClient()
      .from("notification_log")
      .select("public_key, channel, event_type, event_id, attempts")
      .eq("status", "failed")
      .lt("attempts", maxAttempts)
      .order("created_at", { ascending: true })
      .limit(100);

    if (error) {
      this.logger.error(`Failed to fetch retries: ${error.message}`);
      return [];
    }

    return (data ?? []).map((r) => ({
      publicKey: r.public_key,
      channel: r.channel as NotificationChannel,
      eventType: r.event_type as NotificationEventType,
      eventId: r.event_id,
      attempts: r.attempts,
    }));
  }

  /** Check if an event was already successfully delivered via a channel (idempotency check). */
  async isAlreadySent(
    publicKey: string,
    channel: NotificationChannel,
    eventType: NotificationEventType,
    eventId: string,
  ): Promise<boolean> {
    const { data } = await this.supabase
      .getClient()
      .from("notification_log")
      .select("status")
      .eq("public_key", publicKey)
      .eq("channel", channel)
      .eq("event_type", eventType)
      .eq("event_id", eventId)
      .eq("status", "sent")
      .maybeSingle();

    return !!data;
  }
}
