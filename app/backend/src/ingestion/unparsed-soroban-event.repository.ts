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

  async listPending(limit = 100): Promise<UnparsedSorobanEventRecord[]> {
    const { data, error } = await this.supabase
      .getClient()
      .from("unparsed_soroban_events")
      .select("*")
      .eq("status", "pending")
      .order("ledger", { ascending: true })
      .limit(limit);

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
    }));
  }

  async markReplayed(pagingToken: string): Promise<void> {
    await this.updateStatus(pagingToken, "replayed");
  }

  async markFailed(pagingToken: string, errorMessage: string): Promise<void> {
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

  private async updateStatus(pagingToken: string, status: string): Promise<void> {
    const { error } = await this.supabase
      .getClient()
      .from("unparsed_soroban_events")
      .update({ status, updated_at: new Date().toISOString() })
      .eq("paging_token", pagingToken);

    if (error) throw error;
  }
}
