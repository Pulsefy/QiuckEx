import {
  Injectable,
  Logger,
  OnModuleInit,
  OnModuleDestroy,
} from "@nestjs/common";
import { EventEmitter2 } from "@nestjs/event-emitter";
import { Horizon } from "stellar-sdk";

import { AppConfigService } from "../config";
import { HORIZON_BASE_URLS } from "../config/stellar.config";
import {
  SorobanEventParser,
  RawHorizonContractEvent,
} from "./soroban-event.parser";
import { CursorRepository } from "./cursor.repository";
import { EscrowEventRepository } from "./escrow-event.repository";
import type {
  EscrowEvent,
  QuickExContractEvent,
} from "./types/contract-event.types";

/** Milliseconds between reconnect attempts (doubles each retry, capped at MAX_BACKOFF_MS). */
const INITIAL_BACKOFF_MS = 1_000;
const MAX_BACKOFF_MS = 60_000;
const BACKOFF_MULTIPLIER = 2;

export interface IngestionConfig {
  contractId: string;
}

/**
 * Listens to Horizon SSE streams for a QuickEx Soroban contract.
 *
 * Responsibilities:
 *  - Open a streaming subscription starting from the last known cursor.
 *  - Parse each raw Soroban event into a typed domain event.
 *  - Persist escrow events idempotently to Supabase.
 *  - Update the cursor after each successful persist.
 *  - Auto-reconnect with exponential back-off when the stream drops.
 */
@Injectable()
export class StellarIngestionService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(StellarIngestionService.name);

  private server!: Horizon.Server;
  private stopStream: (() => void) | null = null;
  private destroyed = false;
  private reconnectTimer: NodeJS.Timeout | null = null;
  private currentBackoffMs = INITIAL_BACKOFF_MS;

  constructor(
    private readonly config: AppConfigService,
    private readonly cursorRepo: CursorRepository,
    private readonly escrowRepo: EscrowEventRepository,
    private readonly parser: SorobanEventParser,
    private readonly eventEmitter: EventEmitter2,
  ) {}

  onModuleInit(): void {
    const network = this.config.network;
    const horizonUrl = HORIZON_BASE_URLS[network];
    this.server = new Horizon.Server(horizonUrl);
    this.logger.log(
      `Stellar ingestion initialised (${network} → ${horizonUrl})`,
    );
  }

  onModuleDestroy(): void {
    this.destroyed = true;
    this.stopCurrentStream();
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    this.logger.log("Stellar ingestion service stopped.");
  }

  /**
   * Start streaming contract events for the given contract ID.
   * Safe to call multiple times; previous stream is closed first.
   */
  async startStreaming(contractId: string): Promise<void> {
    this.stopCurrentStream();
    await this.openStream(contractId);
  }

  // ---------------------------------------------------------------------------
  // Private stream management
  // ---------------------------------------------------------------------------

  private async openStream(contractId: string): Promise<void> {
    const streamId = `contract:${contractId}`;
    const cursor = await this.cursorRepo.getCursor(streamId);

    this.logger.log(
      cursor
        ? `Resuming stream ${streamId} from cursor ${cursor}`
        : `Starting stream ${streamId} from "now"`,
    );

    // stellar-sdk v13 exposes `server.operationsForAccount` / `server.payments`
    // but for Soroban contract events we use the dedicated endpoint:
    const eventsBuilder = (
      this.server as unknown as {
        contractEvents(contractId: string): {
          cursor(c: string): unknown;
          stream(opts: {
            onmessage: (record: unknown) => void;
            onerror: (err: unknown) => void;
          }): () => void;
        };
      }
    ).contractEvents?.(contractId);

    if (!eventsBuilder) {
      // Fallback: use Horizon's raw SSE endpoint via fetch + EventSource
      this.logger.warn(
        "server.contractEvents() not available on this SDK version; using raw SSE fallback.",
      );
      this.stopStream = this.openRawSseStream(contractId, streamId, cursor);
      return;
    }

    const cursoredBuilder = cursor
      ? eventsBuilder.cursor(cursor)
      : eventsBuilder.cursor("now");

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const stop = (cursoredBuilder as any).stream({
      onmessage: (record: unknown) => {
        void this.handleRecord(record as RawHorizonContractEvent, streamId);
      },
      onerror: (err: unknown) => {
        this.logger.error(`Stream error for ${streamId}: ${String(err)}`);
        this.stopCurrentStream();
        this.scheduleReconnect(contractId);
      },
    }) as () => void;

    this.stopStream = stop;
    this.currentBackoffMs = INITIAL_BACKOFF_MS; // reset on successful open
  }

  /**
   * Fallback SSE stream using the Horizon REST API directly via stellar-sdk's
   * CallBuilder streaming, watching the /contract_events endpoint.
   */
  private openRawSseStream(
    contractId: string,
    streamId: string,
    cursor: string | null,
  ): () => void {
    const horizonUrl = HORIZON_BASE_URLS[this.config.network];
    const url = new URL(`${horizonUrl}/contract_events`);
    url.searchParams.set("contract_id", contractId);
    url.searchParams.set("cursor", cursor ?? "now");
    url.searchParams.set("limit", "200");

    this.logger.debug(`Opening SSE at ${url.toString()}`);

    const es = new EventSource(url.toString());

    es.onmessage = (msg: MessageEvent) => {
      try {
        const record = JSON.parse(
          msg.data as string,
        ) as RawHorizonContractEvent;
        void this.handleRecord(record, streamId);
      } catch (err) {
        this.logger.warn(`Failed to parse SSE message: ${String(err)}`);
      }
    };

    es.onerror = (err) => {
      this.logger.error(`SSE error for ${streamId}: ${String(err)}`);
      es.close();
      this.scheduleReconnect(contractId);
    };

    return () => es.close();
  }

  private stopCurrentStream(): void {
    if (this.stopStream) {
      try {
        this.stopStream();
      } catch {
        // ignore
      }
      this.stopStream = null;
    }
  }

  private scheduleReconnect(contractId: string): void {
    if (this.destroyed) return;

    this.logger.warn(
      `Reconnecting stream for contract ${contractId} in ${this.currentBackoffMs}ms`,
    );

    this.reconnectTimer = setTimeout(() => {
      if (!this.destroyed) {
        void this.openStream(contractId);
      }
    }, this.currentBackoffMs);

    // Exponential back-off with cap
    this.currentBackoffMs = Math.min(
      this.currentBackoffMs * BACKOFF_MULTIPLIER,
      MAX_BACKOFF_MS,
    );
  }

  // ---------------------------------------------------------------------------
  // Event processing
  // ---------------------------------------------------------------------------

  private async handleRecord(
    raw: RawHorizonContractEvent,
    streamId: string,
  ): Promise<void> {
    const event = this.parser.parse(raw);

    if (!event) {
      // Unrecognised or non-QuickEx event; still advance cursor.
      await this.safeUpdateCursor(streamId, raw.paging_token, raw.ledger);
      return;
    }

    this.logger.debug(
      `Processing ${event.eventType} paging_token=${event.pagingToken}`,
    );

    await this.persistEvent(event);
    await this.safeUpdateCursor(streamId, raw.paging_token, raw.ledger);

    // Emit for other services / notification layer
    this.eventEmitter.emit(`stellar.${event.eventType}`, event);
  }

  private async persistEvent(event: QuickExContractEvent): Promise<void> {
    switch (event.eventType) {
      case "EscrowDeposited":
      case "EscrowWithdrawn":
      case "EscrowRefunded":
        await this.escrowRepo.upsertEvent(event as EscrowEvent);
        break;
      default:
        // Other events are emitted but not stored in the DB yet.
        this.logger.debug(
          `Event ${event.eventType} emitted but not persisted.`,
        );
    }
  }

  private async safeUpdateCursor(
    streamId: string,
    pagingToken: string,
    ledger?: number,
  ): Promise<void> {
    try {
      await this.cursorRepo.saveCursor(streamId, pagingToken, ledger);
    } catch (err) {
      // Cursor update failure is non-fatal; we log and continue.
      // The worst case is re-processing a handful of events on the next restart
      // (handled by idempotency constraints).
      this.logger.error(`Failed to update cursor: ${String(err)}`);
    }
  }
}
