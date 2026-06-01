import { Injectable, Logger } from "@nestjs/common";
import { SupabaseService } from "../supabase/supabase.service";
import type { PrivacyToggledEvent } from "./types/contract-event.types";

@Injectable()
export class PrivacyEventRepository {
  private readonly logger = new Logger(PrivacyEventRepository.name);

  constructor(private readonly supabase: SupabaseService) {}

  async upsertEvent(event: PrivacyToggledEvent): Promise<void> {
    const { error } = await this.supabase.getClient()
      .from("privacy_events")
      .upsert(
        {
          event_type: event.eventType,
          owner: event.owner,
          enabled: event.enabled,
          schema_version: event.schemaVersion,
          contract_timestamp: Number(event.contractTimestamp),
          tx_hash: event.txHash,
          ledger_sequence: event.ledgerSequence,
          paging_token: event.pagingToken,
        },
        { onConflict: "tx_hash,event_type,owner", ignoreDuplicates: true },
      );

    if (error) {
      this.logger.error(`Failed to upsert PrivacyToggled for owner ${event.owner}: ${error.message}`);
      throw error;
    }
  }
}
