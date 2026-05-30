import { Injectable, Logger } from "@nestjs/common";
import { SupabaseService } from "../supabase/supabase.service";
import type {
  ContractPausedEvent,
  AdminChangedEvent,
  ContractUpgradedEvent,
  AdminEvent,
} from "./types/contract-event.types";

@Injectable()
export class AdminEventRepository {
  private readonly logger = new Logger(AdminEventRepository.name);

  constructor(private readonly supabase: SupabaseService) {}

  async upsertEvent(event: AdminEvent): Promise<void> {
    const payload = this.buildPayload(event);

    const { error } = await this.supabase.getClient()
      .from("admin_events")
      .upsert(
        {
          event_type: event.eventType,
          payload,
          schema_version: event.schemaVersion,
          contract_timestamp: Number(event.contractTimestamp),
          tx_hash: event.txHash,
          ledger_sequence: event.ledgerSequence,
          paging_token: event.pagingToken,
        },
        { onConflict: "tx_hash,event_type", ignoreDuplicates: true },
      );

    if (error) {
      this.logger.error(`Failed to upsert ${event.eventType} tx=${event.txHash}: ${error.message}`);
      throw error;
    }
  }

  private buildPayload(event: AdminEvent): Record<string, unknown> {
    switch (event.eventType) {
      case "ContractPaused":
        return { admin: (event as ContractPausedEvent).admin, paused: (event as ContractPausedEvent).paused };
      case "AdminChanged":
        return { oldAdmin: (event as AdminChangedEvent).oldAdmin, newAdmin: (event as AdminChangedEvent).newAdmin };
      case "ContractUpgraded":
        return { newWasmHash: (event as ContractUpgradedEvent).newWasmHash, admin: (event as ContractUpgradedEvent).admin };
      default:
        return {};
    }
  }
}
