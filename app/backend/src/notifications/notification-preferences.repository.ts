import { Injectable, Logger } from "@nestjs/common";
import { SupabaseService } from "../supabase/supabase.service";
import {
  NotificationPreference,
  NotificationChannel,
  NotificationEventType,
} from "./types/notification.types";

interface RawPreference {
  id: string;
  public_key: string;
  channel: string;
  email: string | null;
  push_token: string | null;
  webhook_url: string | null;
  webhook_secret: string | null;
  events: string[] | null;
  min_amount_stroops: string | null; // Supabase returns bigint as string
  enabled: boolean;
  created_at?: string;
  updated_at?: string;
}

function mapRow(row: RawPreference): NotificationPreference {
  return {
    id: row.id,
    publicKey: row.public_key,
    channel: row.channel as NotificationChannel,
    email: row.email ?? undefined,
    pushToken: row.push_token ?? undefined,
    webhookUrl: row.webhook_url ?? undefined,
    webhookSecret: row.webhook_secret ?? undefined,
    events: (row.events as NotificationEventType[] | null) ?? null,
    minAmountStroops: BigInt(row.min_amount_stroops ?? "0"),
    enabled: row.enabled,
  };
}

@Injectable()
export class NotificationPreferencesRepository {
  private readonly logger = new Logger(NotificationPreferencesRepository.name);

  constructor(private readonly supabase: SupabaseService) {}

  /** Return all enabled preferences for a given public key. */
  async getEnabledPreferences(
    publicKey: string,
  ): Promise<NotificationPreference[]> {
    const { data, error } = await this.supabase
      .getClient()
      .from("notification_preferences")
      .select("*")
      .eq("public_key", publicKey)
      .eq("enabled", true);

    if (error) {
      this.logger.error(
        `Failed to fetch preferences for ${publicKey}: ${error.message}`,
      );
      throw error;
    }

    return (data ?? []).map(mapRow);
  }

  /** Upsert a preference row (creates or updates). */
  async upsertPreference(
    publicKey: string,
    channel: NotificationChannel,
    options: {
      email?: string;
      pushToken?: string;
      webhookUrl?: string;
      webhookSecret?: string;
      events?: NotificationEventType[] | null;
      minAmountStroops?: bigint;
      enabled?: boolean;
    },
  ): Promise<NotificationPreference> {
    const row = {
      public_key: publicKey,
      channel,
      email: options.email ?? null,
      push_token: options.pushToken ?? null,
      webhook_url: options.webhookUrl ?? null,
      webhook_secret: options.webhookSecret ?? null,
      events: options.events ?? null,
      min_amount_stroops: (options.minAmountStroops ?? 0n).toString(),
      enabled: options.enabled ?? true,
    };

    const { data, error } = await this.supabase
      .getClient()
      .from("notification_preferences")
      .upsert(row, { onConflict: "public_key,channel" })
      .select()
      .single();

    if (error) {
      this.logger.error(
        `Failed to upsert preference for ${publicKey}/${channel}: ${error.message}`,
      );
      throw error;
    }

    return mapRow(data as RawPreference);
  }

  /** Disable a specific channel for a user (soft opt-out). */
  async disableChannel(
    publicKey: string,
    channel: NotificationChannel,
  ): Promise<void> {
    const { error } = await this.supabase
      .getClient()
      .from("notification_preferences")
      .update({ enabled: false })
      .eq("public_key", publicKey)
      .eq("channel", channel);

    if (error) {
      this.logger.error(
        `Failed to disable ${channel} for ${publicKey}: ${error.message}`,
      );
      throw error;
    }
  }

  /** Get a specific webhook preference by ID. */
  async getWebhookById(id: string): Promise<NotificationPreference | null> {
    const { data, error } = await this.supabase
      .getClient()
      .from("notification_preferences")
      .select("*")
      .eq("id", id)
      .eq("channel", "webhook")
      .maybeSingle();

    if (error) {
      this.logger.error(`Failed to fetch webhook ${id}: ${error.message}`);
      throw error;
    }

    return data ? mapRow(data as RawPreference) : null;
  }

  /** Get all webhooks for a public key. */
  async getWebhooksByPublicKey(
    publicKey: string,
  ): Promise<NotificationPreference[]> {
    const { data, error } = await this.supabase
      .getClient()
      .from("notification_preferences")
      .select("*")
      .eq("public_key", publicKey)
      .eq("channel", "webhook");

    if (error) {
      this.logger.error(
        `Failed to fetch webhooks for ${publicKey}: ${error.message}`,
      );
      throw error;
    }

    return (data ?? []).map(mapRow);
  }

  /** Get webhooks for a public key with cursor-based pagination. */
  async getWebhooksByPublicKeyPaginated(
    publicKey: string,
    cursor?: string,
    limit?: number,
  ): Promise<{ data: NotificationPreference[]; next_cursor: string | null; has_more: boolean }> {
    const effectiveLimit = Math.min(100, Math.max(1, limit ?? 20));

    let query = this.supabase
      .getClient()
      .from("notification_preferences")
      .select("*")
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
        `Failed to fetch webhooks for ${publicKey}: ${error.message}`,
      );
      throw error;
    }

    const rows = (data ?? []).map(mapRow);
    const hasMore = rows.length > effectiveLimit;
    const resultData = hasMore ? rows.slice(0, effectiveLimit) : rows;

    let nextCursor: string | null = null;
    if (hasMore && resultData.length > 0) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const lastRaw = (data as any[])[effectiveLimit - 1];
      nextCursor = Buffer.from(
        JSON.stringify({ pk: lastRaw.created_at, id: lastRaw.id }),
        "utf-8",
      ).toString("base64url");
    }

    return { data: resultData, next_cursor: nextCursor, has_more: hasMore };
  }

  /** Delete a webhook preference. */
  async deleteWebhook(id: string): Promise<boolean> {
    const { error } = await this.supabase
      .getClient()
      .from("notification_preferences")
      .delete()
      .eq("id", id)
      .eq("channel", "webhook");

    if (error) {
      this.logger.error(`Failed to delete webhook ${id}: ${error.message}`);
      throw error;
    }

    return true;
  }

  /** Regenerate webhook secret. */
  async regenerateWebhookSecret(
    id: string,
    newSecret: string,
  ): Promise<NotificationPreference> {
    const { data, error } = await this.supabase
      .getClient()
      .from("notification_preferences")
      .update({ webhook_secret: newSecret })
      .eq("id", id)
      .eq("channel", "webhook")
      .select()
      .single();

    if (error) {
      this.logger.error(
        `Failed to regenerate secret for webhook ${id}: ${error.message}`,
      );
      throw error;
    }

    return mapRow(data as RawPreference);
  }
}
