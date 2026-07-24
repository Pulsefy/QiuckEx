import { Injectable, Logger } from "@nestjs/common";

import { SupabaseService } from "../supabase/supabase.service";
import type { RawHorizonContractEvent } from "./soroban-event.parser";

export type UnparsedSorobanEventReason =
  | "unknown_schema_version"
  | "parse_failure";

export interface SaveUnparsedSorobanEventInput {
  raw: RawHorizonContractEvent;
  reason: UnparsedSorobanEventReason;
  eventName?: string | null;
  schemaVersion?: number | null;
  errorMessage?: string | null;
}

export interface UnparsedSorobanEventRecord
  extends SaveUnparsedSorobanEventInput {
  pagingToken: string;
  contractId: string;
  ledger: number;
  transactionHash: string;
  attempts: number;
  status: "pending" | "replayed";
}

@Injectable()
export class UnparsedSorobanEventRepository {
  private readonly logger = new Logger(UnparsedSorobanEventRepository.name);

  constructor(private readonly supabase: SupabaseService) {}

  async save(input: SaveUnparsedSorobanEventInput): Promise<void> {
    const row = {
      paging_token: input.raw.paging_token,
      contract_id: input.raw.contract_id,
      ledger: input.raw.ledger,
      transaction_hash: input.raw.transaction_hash,
      event_name: input.eventName ?? null,
      schema_version: input.schemaVersion ?? null,
      reason: input.reason,
      raw_topics: input.raw.topic,
      raw_payload: input.raw.value,
      raw_event: input.raw,
      error_message: input.errorMessage ?? null,
      status: "pending",
      updated_at: new Date().toISOString(),
    };

    const { error } = await this.supabase
      .getClient()
      .from("unparsed_soroban_events")
      .upsert(row, { onConflict: "paging_token" });

    if (error) {
      this.logger.error(
        `Failed to persist unparsed Soroban event ${input.raw.paging_token}: ${error.message}`,
      );
      throw error;
    }
  }

  async listPending(
    limit = 100,
    filters?: {
      contractId?: string;
      schemaVersion?: number;
      errorType?: UnparsedSorobanEventReason;
    },
  ): Promise<UnparsedSorobanEventRecord[]> {
    let query = this.supabase
      .getClient()
      .from("unparsed_soroban_events")
      .select("*")
      .eq("status", "pending")
      .order("ledger", { ascending: true })
      .limit(limit);

    if (filters?.contractId) {
      query = query.eq("contract_id", filters.contractId);
    }
    if (filters?.schemaVersion !== undefined) {
      query = query.eq("schema_version", filters.schemaVersion);
    }
    if (filters?.errorType) {
      query = query.eq("reason", filters.errorType);
    }

    const { data, error } = await query;

    if (error) {
      this.logger.error(`Failed to list unparsed Soroban events: ${error.message}`);
      throw error;
    }

    return (data ?? []).map((row: Record<string, unknown>) => ({
      raw: row.raw_event as RawHorizonContractEvent,
      reason: row.reason as UnparsedSorobanEventReason,
      eventName: (row.event_name as string | null) ?? null,
      schemaVersion:
        row.schema_version === null || row.schema_version === undefined
          ? null
          : Number(row.schema_version),
      errorMessage: (row.error_message as string | null) ?? null,
      pagingToken: String(row.paging_token),
      contractId: String(row.contract_id),
      ledger: Number(row.ledger),
      transactionHash: String(row.transaction_hash),
      attempts: Number(row.attempts ?? 0),
      status: row.status as "pending" | "replayed",
    }));
  }

  async markReplayed(pagingToken: string): Promise<void> {
    await this.updateStatus(pagingToken, "replayed");
  }

  private async incrementAttempts(pagingToken: string): Promise<number> {
    const current = await this.getByPagingToken(pagingToken);
    if (!current) return 0;
    const newAttempts = current.attempts + 1;
    await this.supabase
      .getClient()
      .from("unparsed_soroban_events")
      .update({ attempts: newAttempts })
      .eq("paging_token", pagingToken);
    return newAttempts;
  }

  async markFailed(pagingToken: string, errorMessage: string): Promise<void> {
    await this.incrementAttempts(pagingToken);
    const { error } = await this.supabase
      .getClient()
      .from("unparsed_soroban_events")
      .update({
        status: "pending",
        error_message: errorMessage,
        updated_at: new Date().toISOString(),
      })
      .eq("paging_token", pagingToken);

    if (error) throw error;
  }

  async getByPagingToken(pagingToken: string): Promise<UnparsedSorobanEventRecord | null> {
    const { data, error } = await this.supabase
      .getClient()
      .from("unparsed_soroban_events")
      .select("*")
      .eq("paging_token", pagingToken)
      .single();

    if (error) {
      if (error.code === "PGRST116") return null; // No rows returned
      this.logger.error(`Failed to get unparsed event: ${error.message}`);
      throw error;
    }

    return {
      raw: data.raw_event as RawHorizonContractEvent,
      reason: data.reason as UnparsedSorobanEventReason,
      eventName: (data.event_name as string | null) ?? null,
      schemaVersion:
        data.schema_version === null || data.schema_version === undefined
          ? null
          : Number(data.schema_version),
      errorMessage: (data.error_message as string | null) ?? null,
      pagingToken: String(data.paging_token),
      contractId: String(data.contract_id),
      ledger: Number(data.ledger),
      transactionHash: String(data.transaction_hash),
      attempts: Number(data.attempts ?? 0),
      status: data.status as "pending" | "replayed",
    };
  }

  private async updateStatus(pagingToken: string, status: string): Promise<void> {
    await this.incrementAttempts(pagingToken);
    const { error } = await this.supabase
      .getClient()
      .from("unparsed_soroban_events")
      .update({ 
        status,
        updated_at: new Date().toISOString() 
      })
      .eq("paging_token", pagingToken);

    if (error) throw error;
  }
}