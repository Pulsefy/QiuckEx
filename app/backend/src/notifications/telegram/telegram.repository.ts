import { Injectable, Logger } from "@nestjs/common";
import { SupabaseService } from "../../supabase/supabase.service";

export interface TelegramUserMapping {
  id: string;
  telegramId: number;
  username?: string;
  publicKey: string;
  isVerified: boolean;
  verificationCode?: string;
  enabled: boolean;
  minAmountStroops: bigint;
  lastNotificationAt?: Date;
  createdAt: Date;
  updatedAt: Date;
}

// Define the raw database row interface
interface RawTelegramUserMapping {
  id: string;
  telegram_id: number;
  username: string | null;
  public_key: string;
  is_verified: boolean;
  verification_code: string | null;
  enabled: boolean;
  min_amount_stroops: string;
  last_notification_at: string | null;
  created_at: string;
  updated_at: string;
}

@Injectable()
export class TelegramRepository {
  private readonly logger = new Logger(TelegramRepository.name);

  constructor(private readonly supabase: SupabaseService) {}

  /**
   * Find a Telegram user mapping by Telegram ID
   */
  async findByTelegramId(
    telegramId: number,
  ): Promise<TelegramUserMapping | null> {
    const { data, error } = await this.supabase
      .getClient()
      .from("telegram_user_mappings")
      .select("*")
      .eq("telegram_id", telegramId)
      .single();

    if (error && error.code !== "PGRST116") {
      // PGRST116 = not found
      this.logger.error(
        `Failed to fetch Telegram mapping for ${telegramId}: ${error.message}`,
      );
      throw error;
    }

    return data ? this.mapRow(data) : null;
  }

  /**
   * Find a Telegram user mapping by public key
   */
  async findByPublicKey(
    publicKey: string,
  ): Promise<TelegramUserMapping | null> {
    const { data, error } = await this.supabase
      .getClient()
      .from("telegram_user_mappings")
      .select("*")
      .eq("public_key", publicKey)
      .single();

    if (error && error.code !== "PGRST116") {
      this.logger.error(
        `Failed to fetch Telegram mapping for ${publicKey}: ${error.message}`,
      );
      throw error;
    }

    return data ? this.mapRow(data) : null;
  }

  /**
   * Create or update a Telegram user mapping
   */
  async upsertMapping(mapping: {
    telegramId: number;
    username?: string;
    publicKey: string;
    isVerified?: boolean;
    verificationCode?: string;
    enabled?: boolean;
    minAmountStroops?: bigint;
  }): Promise<TelegramUserMapping> {
    const row = {
      telegram_id: mapping.telegramId,
      username: mapping.username ?? null,
      public_key: mapping.publicKey,
      is_verified: mapping.isVerified ?? false,
      verification_code: mapping.verificationCode ?? null,
      enabled: mapping.enabled ?? true,
      min_amount_stroops: (mapping.minAmountStroops ?? 0n).toString(),
    };

    const { data, error } = await this.supabase
      .getClient()
      .from("telegram_user_mappings")
      .upsert(row, { onConflict: "telegram_id" })
      .select()
      .single();

    if (error) {
      this.logger.error(
        `Failed to upsert Telegram mapping for ${mapping.telegramId}: ${error.message}`,
      );
      throw error;
    }

    return this.mapRow(data);
  }

  /**
   * Update verification status
   */
  async markAsVerified(
    telegramId: number,
  ): Promise<TelegramUserMapping | null> {
    const { data, error } = await this.supabase
      .getClient()
      .from("telegram_user_mappings")
      .update({ is_verified: true, verification_code: null })
      .eq("telegram_id", telegramId)
      .select()
      .single();

    if (error) {
      this.logger.error(
        `Failed to mark Telegram user ${telegramId} as verified: ${error.message}`,
      );
      throw error;
    }

    return this.mapRow(data);
  }

  /**
   * Enable or disable notifications for a Telegram user
   */
  async setEnabled(
    telegramId: number,
    enabled: boolean,
  ): Promise<TelegramUserMapping | null> {
    const { data, error } = await this.supabase
      .getClient()
      .from("telegram_user_mappings")
      .update({ enabled })
      .eq("telegram_id", telegramId)
      .select()
      .single();

    if (error) {
      this.logger.error(
        `Failed to set enabled=${enabled} for Telegram user ${telegramId}: ${error.message}`,
      );
      throw error;
    }

    return this.mapRow(data);
  }

  /**
   * Update minimum amount threshold
   */
  async setMinAmount(
    telegramId: number,
    minAmountStroops: bigint,
  ): Promise<TelegramUserMapping | null> {
    const { data, error } = await this.supabase
      .getClient()
      .from("telegram_user_mappings")
      .update({ min_amount_stroops: minAmountStroops.toString() })
      .eq("telegram_id", telegramId)
      .select()
      .single();

    if (error) {
      this.logger.error(
        `Failed to update min amount for Telegram user ${telegramId}: ${error.message}`,
      );
      throw error;
    }

    return this.mapRow(data);
  }

  /**
   * Update last notification timestamp
   */
  async updateLastNotification(
    telegramId: number,
  ): Promise<TelegramUserMapping | null> {
    const { data, error } = await this.supabase
      .getClient()
      .from("telegram_user_mappings")
      .update({ last_notification_at: new Date().toISOString() })
      .eq("telegram_id", telegramId)
      .select()
      .single();

    if (error) {
      this.logger.error(
        `Failed to update last notification for Telegram user ${telegramId}: ${error.message}`,
      );
      throw error;
    }

    return this.mapRow(data);
  }

  /**
   * Delete a Telegram user mapping
   */
  async deleteMapping(telegramId: number): Promise<void> {
    const { error } = await this.supabase
      .getClient()
      .from("telegram_user_mappings")
      .delete()
      .eq("telegram_id", telegramId);

    if (error) {
      this.logger.error(
        `Failed to delete Telegram mapping for ${telegramId}: ${error.message}`,
      );
      throw error;
    }
  }

  /**
   * Log a Telegram notification delivery attempt
   */
  async logNotification(params: {
    telegramId: number;
    publicKey: string;
    eventType: string;
    eventId: string;
    status: "pending" | "sent" | "failed";
    errorMessage?: string;
    telegramMessageId?: number;
  }): Promise<void> {
    const row = {
      telegram_id: params.telegramId,
      public_key: params.publicKey,
      event_type: params.eventType,
      event_id: params.eventId,
      status: params.status,
      attempts: 1,
      last_error: params.errorMessage ?? null,
      telegram_message_id: params.telegramMessageId ?? null,
    };

    const { error } = await this.supabase
      .getClient()
      .from("telegram_notification_log")
      .insert(row);

    if (error) {
      this.logger.error(
        `Failed to log Telegram notification for ${params.eventId}: ${error.message}`,
      );
      throw error;
    }
  }

  /**
   * Get all enabled Telegram mappings for batch notifications
   */
  async getEnabledMappings(): Promise<TelegramUserMapping[]> {
    const { data, error } = await this.supabase
      .getClient()
      .from("telegram_user_mappings")
      .select("*")
      .eq("is_verified", true)
      .eq("enabled", true);

    if (error) {
      this.logger.error(
        `Failed to fetch enabled Telegram mappings: ${error.message}`,
      );
      throw error;
    }

    return (data ?? []).map(this.mapRow);
  }

  private mapRow(row: RawTelegramUserMapping): TelegramUserMapping {
    return {
      id: row.id,
      telegramId: Number(row.telegram_id),
      username: row.username ?? undefined,
      publicKey: row.public_key,
      isVerified: row.is_verified,
      verificationCode: row.verification_code ?? undefined,
      enabled: row.enabled,
      minAmountStroops: BigInt(row.min_amount_stroops ?? "0"),
      lastNotificationAt: row.last_notification_at
        ? new Date(row.last_notification_at)
        : undefined,
      createdAt: new Date(row.created_at),
      updatedAt: new Date(row.updated_at),
    };
  }
}