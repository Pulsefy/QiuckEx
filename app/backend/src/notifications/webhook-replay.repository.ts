import { Injectable, Logger } from "@nestjs/common";
import { SupabaseService } from "../supabase/supabase.service";

export type WebhookReplayLogStatus =
  | "queued"
  | "succeeded"
  | "failed"
  | "rejected";

export interface WebhookReplayLogEntry {
  id: string;
  webhookId: string;
  publicKey: string;
  eventType: string;
  eventId: string;
  status: WebhookReplayLogStatus;
  reason?: string;
  triggeredBy: string;
  deliverySuccess?: boolean;
  createdAt: string;
}

@Injectable()
export class WebhookReplayRepository {
  private readonly logger = new Logger(WebhookReplayRepository.name);

  constructor(private readonly supabase: SupabaseService) {}

  async createReplayLog(params: {
    webhookId: string;
    publicKey: string;
    eventType: string;
    eventId: string;
    status: WebhookReplayLogStatus;
    reason?: string;
    triggeredBy?: string;
    deliverySuccess?: boolean;
  }): Promise<WebhookReplayLogEntry | null> {
    const { data, error } = await this.supabase
      .getClient()
      .from("webhook_replay_log")
      .insert({
        webhook_id: params.webhookId,
        public_key: params.publicKey,
        event_type: params.eventType,
        event_id: params.eventId,
        status: params.status,
        reason: params.reason ?? null,
        triggered_by: params.triggeredBy ?? "api",
        delivery_success: params.deliverySuccess ?? null,
      })
      .select(
        "id, webhook_id, public_key, event_type, event_id, status, reason, triggered_by, delivery_success, created_at",
      )
      .single();

    if (error) {
      this.logger.warn(`Failed to persist webhook replay log: ${error.message}`);
      return null;
    }

    return this.mapRow(data);
  }

  async updateReplayLog(
    id: string,
    updates: {
      status: WebhookReplayLogStatus;
      deliverySuccess?: boolean;
      reason?: string;
    },
  ): Promise<void> {
    const { error } = await this.supabase
      .getClient()
      .from("webhook_replay_log")
      .update({
        status: updates.status,
        delivery_success: updates.deliverySuccess ?? null,
        reason: updates.reason ?? null,
      })
      .eq("id", id);

    if (error) {
      this.logger.warn(`Failed to update webhook replay log: ${error.message}`);
    }
  }

  async getReplayStats(
    publicKey: string,
    eventType: string,
    eventId: string,
  ): Promise<{ replayCount: number; lastReplayAt?: string }> {
    const { data, error } = await this.supabase
      .getClient()
      .from("webhook_replay_log")
      .select("created_at")
      .eq("public_key", publicKey)
      .eq("event_type", eventType)
      .eq("event_id", eventId)
      .order("created_at", { ascending: false });

    if (error) {
      this.logger.warn(`Failed to fetch replay stats: ${error.message}`);
      return { replayCount: 0 };
    }

    const rows = data ?? [];
    return {
      replayCount: rows.length,
      lastReplayAt: rows[0]?.created_at ?? undefined,
    };
  }

  async listReplayLogs(
    webhookId: string,
    limit = 50,
  ): Promise<WebhookReplayLogEntry[]> {
    const effectiveLimit = Math.min(100, Math.max(1, limit));

    const { data, error } = await this.supabase
      .getClient()
      .from("webhook_replay_log")
      .select(
        "id, webhook_id, public_key, event_type, event_id, status, reason, triggered_by, delivery_success, created_at",
      )
      .eq("webhook_id", webhookId)
      .order("created_at", { ascending: false })
      .limit(effectiveLimit);

    if (error) {
      this.logger.warn(`Failed to list webhook replay logs: ${error.message}`);
      return [];
    }

    return (data ?? []).map((row) => this.mapRow(row));
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private mapRow(row: any): WebhookReplayLogEntry {
    return {
      id: row.id,
      webhookId: row.webhook_id,
      publicKey: row.public_key,
      eventType: row.event_type,
      eventId: row.event_id,
      status: row.status as WebhookReplayLogStatus,
      reason: row.reason ?? undefined,
      triggeredBy: row.triggered_by,
      deliverySuccess: row.delivery_success ?? undefined,
      createdAt: row.created_at,
    };
  }
}
