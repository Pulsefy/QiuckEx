import { Injectable, Logger } from "@nestjs/common";
import { createClient, SupabaseClient } from "@supabase/supabase-js";

import { AppConfigService } from "../config";
import {
  EscrowDbStatus,
  EscrowRecord,
  PaymentDbStatus,
  PaymentRecord,
} from "../reconciliation/types/reconciliation.types";
import {
  SupabaseError,
  SupabaseNetworkError,
  SupabaseUniqueConstraintError,
} from "./supabase.errors";

@Injectable()
export class SupabaseService {
  private readonly logger = new Logger(SupabaseService.name);
  private readonly client: SupabaseClient;

  constructor(private readonly configService: AppConfigService) {
    // Environment variables are validated at startup via Joi schema,
    // so we can safely access them here without null checks
    const url = this.configService.supabaseUrl;
    const anonKey = this.configService.supabaseAnonKey;

    this.client = createClient(url, anonKey, {
      auth: {
        persistSession: false,
      },
    });

    this.logger.log("Supabase client initialized successfully");
  }

  /**
   * Expose the underlying SupabaseClient for direct table access in repositories.
   */
  getClient(): SupabaseClient {
    return this.client;
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private handleError(error: any): never {
    if (error?.code === "23505") {
      throw new SupabaseUniqueConstraintError(
        error.message || "Unique constraint violation",
        error,
      );
    }
    // Match common network/timeout issues or PostgREST generic errors
    if (
      error?.message?.toLowerCase().includes("fetch") ||
      error?.message?.toLowerCase().includes("network") ||
      error?.code === "PGRST301"
    ) {
      throw new SupabaseNetworkError(
        error.message || "Network error connecting to Supabase",
        error,
      );
    }
    throw new SupabaseError(
      error?.message || "Unknown Supabase error",
      error?.code,
      error,
    );
  }

  async insertUsername(username: string, publicKey: string): Promise<void> {
    const { error } = await this.client.from("usernames").insert({
      username,
      public_key: publicKey,
    });
    if (error) this.handleError(error);
  }

  async countUsernamesByPublicKey(publicKey: string): Promise<number> {
    const { count, error } = await this.client
      .from("usernames")
      .select("*", { count: "exact", head: true })
      .eq("public_key", publicKey);
    if (error) this.handleError(error);
    return count ?? 0;
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  async listUsernamesByPublicKey(publicKey: string): Promise<any[]> {
    const { data, error } = await this.client
      .from("usernames")
      .select("id, username, public_key, created_at")
      .eq("public_key", publicKey)
      .order("created_at", { ascending: true });
    if (error) this.handleError(error);
    return data ?? [];
  }

  // ---------------------------------------------------------------------------
  // Reconciliation helpers
  // ---------------------------------------------------------------------------

  async fetchPendingEscrows(
    statuses: EscrowDbStatus[],
    limit: number,
  ): Promise<EscrowRecord[]> {
    const { data, error } = await this.client
      .from("escrow_records")
      .select("*")
      .in("status", statuses)
      .order("updated_at", { ascending: true })
      .limit(limit);
    if (error) this.handleError(error);
    return (data as EscrowRecord[]) ?? [];
  }

  async fetchPendingPayments(
    statuses: PaymentDbStatus[],
    limit: number,
  ): Promise<PaymentRecord[]> {
    const { data, error } = await this.client
      .from("payment_records")
      .select("*")
      .in("status", statuses)
      .order("updated_at", { ascending: true })
      .limit(limit);
    if (error) this.handleError(error);
    return (data as PaymentRecord[]) ?? [];
  }

  async updateEscrowStatus(id: string, status: EscrowDbStatus): Promise<void> {
    const { error } = await this.client
      .from("escrow_records")
      .update({ status, updated_at: new Date().toISOString() })
      .eq("id", id);
    if (error) this.handleError(error);
  }

  async updatePaymentStatus(
    id: string,
    status: PaymentDbStatus,
  ): Promise<void> {
    const { error } = await this.client
      .from("payment_records")
      .update({ status, updated_at: new Date().toISOString() })
      .eq("id", id);
    if (error) this.handleError(error);
  }

  async flagIrreconcilableEscrow(id: string, reason: string): Promise<void> {
    const { error } = await this.client
      .from("escrow_records")
      .update({
        status: "irreconcilable",
        reconciliation_note: reason,
        updated_at: new Date().toISOString(),
      })
      .eq("id", id);
    if (error) this.handleError(error);
  }

  async flagIrreconcilablePayment(id: string, reason: string): Promise<void> {
    const { error } = await this.client
      .from("payment_records")
      .update({
        status: "irreconcilable",
        reconciliation_note: reason,
        updated_at: new Date().toISOString(),
      })
      .eq("id", id);
    if (error) this.handleError(error);
  }

  async checkHealth(): Promise<boolean> {
    try {
      const { error } = await this.client
        .from("usernames")
        .select("id")
        .limit(1);
      if (error) {
        this.logger.warn(`Supabase health check failed: ${error.message}`);
        return false;
      }
      return true;
    } catch (err) {
      this.logger.warn(
        `Supabase health check threw an error: ${(err as Error).message}`,
      );
      return false;
    }
  }
}
