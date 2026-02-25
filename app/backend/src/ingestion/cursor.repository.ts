import { Injectable, Logger } from "@nestjs/common";
import { SupabaseService } from "../supabase/supabase.service";

export interface CursorRecord {
  id: string;
  paging_token: string;
  ledger_sequence: number | null;
  updated_at: string;
}

/**
 * Manages ingestion cursors (last processed Horizon paging token) in Supabase.
 * Uses an UPSERT so a missing cursor row is created on first write.
 */
@Injectable()
export class CursorRepository {
  private readonly logger = new Logger(CursorRepository.name);

  constructor(private readonly supabase: SupabaseService) {}

  /**
   * Return the stored paging token for a stream, or null if none exists yet.
   */
  async getCursor(streamId: string): Promise<string | null> {
    const client = this.supabase.getClient();
    const { data, error } = await client
      .from("cursors")
      .select("paging_token")
      .eq("id", streamId)
      .maybeSingle();

    if (error) {
      this.logger.error(
        `Failed to read cursor for ${streamId}: ${error.message}`,
      );
      throw error;
    }

    return data?.paging_token ?? null;
  }

  /**
   * Persist the latest paging token for a stream (upsert).
   */
  async saveCursor(
    streamId: string,
    pagingToken: string,
    ledgerSequence?: number,
  ): Promise<void> {
    const client = this.supabase.getClient();
    const { error } = await client.from("cursors").upsert(
      {
        id: streamId,
        paging_token: pagingToken,
        ledger_sequence: ledgerSequence ?? null,
        updated_at: new Date().toISOString(),
      },
      { onConflict: "id" },
    );

    if (error) {
      this.logger.error(
        `Failed to save cursor for ${streamId}: ${error.message}`,
      );
      throw error;
    }

    this.logger.debug(`Cursor saved: ${streamId} → ${pagingToken}`);
  }
}
