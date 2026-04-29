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

  async markSent(
    publicKey: string,
    channel: NotificationChannel,
    eventType: NotificationEventType,
    eventId: string,
    providerMessageId?: string,
    httpStatus?: number,
    responseBody?: string,
  ): Promise<void> {
    const updateData: Record<string, unknown> = {
      status: "sent",
      provider_message_id: providerMessageId ?? null,
      last_error: null,
    };

    if (channel === "webhook") {
      updateData.webhook_response_status = httpStatus ?? null;
      updateData.webhook_response_body = responseBody ?? null;
      updateData.webhook_delivered_at = new Date().toISOString();
    }

    const { error } = await this.supabase
      .getClient()
      .from("notification_log")
      .update(updateData)
      .eq("public_key", publicKey)
      .eq("channel", channel)
      .eq("event_type", eventType)
      .eq("event_id", eventId);

    if (error) {
      this.logger.warn(`Failed to mark notification sent: ${error.message}`);
    }
  }

  async markFailed(
    publicKey: string,
    channel: NotificationChannel,
    eventType: NotificationEventType,
    eventId: string,
    errorMessage: string,
  ): Promise<void> {
    const client = this.supabase.getClient();

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

  async getPendingRetries(maxAttempts: number): Promise<
    Array<{
      publicKey: string;
      channel: NotificationChannel;
      eventType: NotificationEventType;
      eventId: string;
      attempts: number;
      lastFailedAt?: string;
    }>
  > {
    const { data, error } = await this.supabase
      .getClient()
      .from("notification_log")
      .select("public_key, channel, event_type, event_id, attempts, updated_at")
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
      lastFailedAt: r.updated_at ?? undefined,
    }));
  }

  /** Move a log entry to DLQ status after exhausting all retries. */
  async markDlq(
    publicKey: string,
    channel: NotificationChannel,
    eventType: NotificationEventType,
    eventId: string,
    lastError: string,
  ): Promise<void> {
    const { error } = await this.supabase
      .getClient()
      .from("notification_log")
      .update({ status: "dlq", last_error: lastError })
      .eq("public_key", publicKey)
      .eq("channel", channel)
      .eq("event_type", eventType)
      .eq("event_id", eventId);

    if (error) {
      this.logger.warn(`Failed to mark notification as DLQ: ${error.message}`);
    }
  }

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

  async getWebhookDeliveryLogs(
    publicKey: string,
    limit = 50,
  ): Promise<
    Array<{
      id: string;
      eventType: NotificationEventType;
      eventId: string;
      status: string;
      attempts: number;
      lastError?: string;
      httpStatus?: number;
      responseBody?: string;
      createdAt: string;
      deliveredAt?: string;
    }>
  > {
    const { data, error } = await this.supabase
      .getClient()
      .from("notification_log")
      .select(
        "id, event_type, event_id, status, attempts, last_error, webhook_response_status, webhook_response_body, created_at, webhook_delivered_at",
      )
      .eq("public_key", publicKey)
      .eq("channel", "webhook")
      .order("created_at", { ascending: false })
      .limit(limit);

    if (error) {
      this.logger.error(
        `Failed to fetch webhook logs for ${publicKey}: ${error.message}`,
      );
      return [];
    }

    return (data ?? []).map((r) => ({
      id: r.id,
      eventType: r.event_type as NotificationEventType,
      eventId: r.event_id,
      status: r.status,
      attempts: r.attempts,
      lastError: r.last_error ?? undefined,
      httpStatus: r.webhook_response_status ?? undefined,
      responseBody: r.webhook_response_body ?? undefined,
      createdAt: r.created_at,
      deliveredAt: r.webhook_delivered_at ?? undefined,
    }));
  }

  /** Cursor-paginated variant of getWebhookDeliveryLogs. */
  async getWebhookDeliveryLogsPaginated(
    publicKey: string,
    limit = 50,
    cursor?: string,
  ): Promise<{
    data: Array<{
      id: string;
      eventType: NotificationEventType;
      eventId: string;
      status: string;
      attempts: number;
      lastError?: string;
      httpStatus?: number;
      responseBody?: string;
      createdAt: string;
      deliveredAt?: string;
    }>;
    next_cursor: string | null;
    has_more: boolean;
  }> {
    const effectiveLimit = Math.min(100, Math.max(1, limit));

    let query = this.supabase
      .getClient()
      .from("notification_log")
      .select(
        "id, event_type, event_id, status, attempts, last_error, webhook_response_status, webhook_response_body, created_at, webhook_delivered_at",
      )
      .eq("public_key", publicKey)
      .eq("channel", "webhook");

    // Decode cursor
    if (cursor) {
      try {
        const json = Buffer.from(cursor, "base64url").toString("utf-8");
        const parsed = JSON.parse(json);
        if (typeof parsed.pk === "string" && typeof parsed.id === "string") {
          query = query
            .lt("created_at", parsed.pk)
            .or(`created_at.eq.${parsed.pk},id.lt.${parsed.id}`);
        }
      } catch {
        // invalid cursor
      }
    }

    query = query
      .order("created_at", { ascending: false })
      .order("id", { ascending: false })
      .limit(effectiveLimit + 1);

    const { data, error } = await query;

    if (error) {
      this.logger.error(
        `Failed to fetch webhook logs for ${publicKey}: ${error.message}`,
      );
      return { data: [], next_cursor: null, has_more: false };
    }

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const rawRows = (data ?? []) as any[];
    const hasMore = rawRows.length > effectiveLimit;
    const pageRows = hasMore ? rawRows.slice(0, effectiveLimit) : rawRows;

    const mapped = pageRows.map((r) => ({
      id: r.id,
      eventType: r.event_type as NotificationEventType,
      eventId: r.event_id,
      status: r.status,
      attempts: r.attempts,
      lastError: r.last_error ?? undefined,
      httpStatus: r.webhook_response_status ?? undefined,
      responseBody: r.webhook_response_body ?? undefined,
      createdAt: r.created_at,
      deliveredAt: r.webhook_delivered_at ?? undefined,
    }));

    let nextCursor: string | null = null;
    if (hasMore && pageRows.length > 0) {
      const last = pageRows[pageRows.length - 1];
      nextCursor = Buffer.from(
        JSON.stringify({ pk: last.created_at, id: last.id }),
        "utf-8",
      ).toString("base64url");
    }

    return { data: mapped, next_cursor: nextCursor, has_more: hasMore };
  }

  /** Get webhook stats for a specific public key. */
  async getWebhookStats(publicKey: string): Promise<{
    totalSent: number;
    totalFailed: number;
    pendingRetries: number;
    lastDeliveryAt?: string;
    lastError?: string;
  }> {
    const client = this.supabase.getClient();

    // Get counts by status
    const { data: sentData } = await client
      .from("notification_log")
      .select("id", { count: "exact", head: true })
      .eq("public_key", publicKey)
      .eq("channel", "webhook")
      .eq("status", "sent");

    const { data: failedData } = await client
      .from("notification_log")
      .select("id", { count: "exact", head: true })
      .eq("public_key", publicKey)
      .eq("channel", "webhook")
      .eq("status", "failed");

    const pendingRetries = await this.getPendingRetries(3);
    const pendingForUser = pendingRetries.filter(
      (r) => r.publicKey === publicKey && r.channel === "webhook",
    );

    const { data: lastDelivery } = await client
      .from("notification_log")
      .select("webhook_delivered_at, last_error")
      .eq("public_key", publicKey)
      .eq("channel", "webhook")
      .eq("status", "sent")
      .order("webhook_delivered_at", { ascending: false })
      .limit(1)
      .maybeSingle();

    return {
      totalSent: sentData?.length ?? 0,
      totalFailed: failedData?.length ?? 0,
      pendingRetries: pendingForUser.length,
      lastDeliveryAt: lastDelivery?.webhook_delivered_at ?? undefined,
      lastError: lastDelivery?.last_error ?? undefined,
    };
  }
}
