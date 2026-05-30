import { Injectable, Logger } from "@nestjs/common";
import { SupabaseService } from "../supabase/supabase.service";
import type {
  StealthEvent,
  EphemeralKeyRegisteredEvent,
} from "./types/contract-event.types";

@Injectable()
export class StealthEventRepository {
  private readonly logger = new Logger(StealthEventRepository.name);

  constructor(private readonly supabase: SupabaseService) {}

  async upsertEvent(event: StealthEvent): Promise<void> {
    const isRegistered = event.eventType === "EphemeralKeyRegistered";
    const registered = isRegistered ? (event as EphemeralKeyRegisteredEvent) : null;

    const { error } = await this.supabase.getClient()
      .from("stealth_events")
      .upsert(
        {
          event_type: event.eventType,
          stealth_address: event.stealthAddress,
          counterparty: isRegistered ? registered!.ephPub : (event as { recipient: string }).recipient,
          token: event.token,
          amount: event.amount.toString(),
          expires_at: registered
            ? new Date(Number(registered.expiresAt) * 1000).toISOString()
            : null,
          schema_version: event.schemaVersion,
          contract_timestamp: Number(event.contractTimestamp),
          tx_hash: event.txHash,
          ledger_sequence: event.ledgerSequence,
          paging_token: event.pagingToken,
        },
        { onConflict: "tx_hash,event_type,stealth_address", ignoreDuplicates: true },
      );

    if (error) {
      this.logger.error(
        `Failed to upsert ${event.eventType} stealth=${event.stealthAddress}: ${error.message}`,
      );
      throw error;
    }
  }
}
