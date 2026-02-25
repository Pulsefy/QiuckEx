import { Injectable, Logger } from "@nestjs/common";
import { SupabaseService } from "../supabase/supabase.service";
import type {
  EscrowEvent,
  EscrowDepositedEvent,
} from "./types/contract-event.types";

/**
 * Persists escrow domain events to Supabase.
 * All inserts use ON CONFLICT DO NOTHING so replaying the same event is safe.
 */
@Injectable()
export class EscrowEventRepository {
  private readonly logger = new Logger(EscrowEventRepository.name);

  constructor(private readonly supabase: SupabaseService) {}

  /**
   * Idempotently insert an escrow event.
   * The unique constraint on (tx_hash, commitment, event_type) ensures
   * that re-processing the same event is a no-op.
   */
  async upsertEvent(event: EscrowEvent): Promise<void> {
    const client = this.supabase.getClient();

    const row: Record<string, unknown> = {
      event_type: event.eventType,
      commitment: event.commitment,
      owner: event.owner,
      token: event.token,
      amount: event.amount.toString(),
      contract_timestamp: Number(event.contractTimestamp),
      tx_hash: event.txHash,
      ledger_sequence: event.ledgerSequence,
      paging_token: event.pagingToken,
      expires_at:
        event.eventType === "EscrowDeposited"
          ? new Date(
              Number((event as EscrowDepositedEvent).expiresAt) * 1000,
            ).toISOString()
          : null,
    };

    const { error } = await client
      .from("escrow_events")
      .upsert(row, {
        onConflict: "tx_hash,commitment,event_type",
        ignoreDuplicates: true,
      });

    if (error) {
      this.logger.error(
        `Failed to upsert escrow event ${event.eventType} for commitment ${event.commitment}: ${error.message}`,
      );
      throw error;
    }

    this.logger.debug(
      `Persisted ${event.eventType} commitment=${event.commitment} ledger=${event.ledgerSequence}`,
    );
  }
}
