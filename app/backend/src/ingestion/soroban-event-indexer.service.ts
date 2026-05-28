import { Injectable, Logger } from "@nestjs/common";
import { EventEmitter2 } from "@nestjs/event-emitter";

import { AppConfigService } from "../config";
import { HORIZON_BASE_URLS } from "../config/stellar.config";
import { MetricsService } from "../metrics/metrics.service";
import { SorobanEventParser, RawHorizonContractEvent } from "./soroban-event.parser";
import { IndexerCheckpointRepository } from "./indexer-checkpoint.repository";
import { EscrowEventRepository } from "./escrow-event.repository";
import { PrivacyEventRepository } from "./privacy-event.repository";
import { AdminEventRepository } from "./admin-event.repository";
import { StealthEventRepository } from "./stealth-event.repository";
import type {
  QuickExContractEvent,
  EscrowEvent,
  AdminEvent,
  StealthEvent,
} from "./types/contract-event.types";

/** Number of events fetched per Horizon page. */
const PAGE_LIMIT = 200;

export interface LedgerRangeResult {
  fromLedger: number;
  toLedger: number;
  processed: number;
  persisted: number;
  skippedUnknownSchema: number;
}

/**
 * Polls Soroban contract events by ledger range from Horizon's REST API.
 *
 * Responsibilities:
 *  - Fetch events page-by-page for a given [fromLedger, toLedger] range.
 *  - Parse each event with schema-version awareness.
 *  - Persist all event domains idempotently (escrow, privacy, admin, stealth).
 *  - Advance the durable checkpoint after each page so a crash is recoverable.
 *  - Emit domain events for downstream consumers.
 *
 * Reconciliation / reindex: calling `indexLedgerRange` with `force=true` skips
 * the checkpoint read and re-processes the full range. Idempotent upserts ensure
 * no duplicates are created.
 */
@Injectable()
export class SorobanEventIndexerService {
  private readonly logger = new Logger(SorobanEventIndexerService.name);
  private readonly horizonUrl: string;

  constructor(
    private readonly config: AppConfigService,
    private readonly checkpointRepo: IndexerCheckpointRepository,
    private readonly escrowRepo: EscrowEventRepository,
    private readonly privacyRepo: PrivacyEventRepository,
    private readonly adminRepo: AdminEventRepository,
    private readonly stealthRepo: StealthEventRepository,
    private readonly metrics: MetricsService,
    private readonly eventEmitter: EventEmitter2,
  ) {
    this.horizonUrl = HORIZON_BASE_URLS[this.config.network];

    // Wire the parser's unknown-schema-version callback to metrics.
    this.parser = new SorobanEventParser((eventName, version, pagingToken) => {
      this.logger.warn(
        `Unknown schema_version=${version} for event ${eventName} paging_token=${pagingToken}`,
      );
      this.metrics.recordUnknownSchemaVersion(eventName, version);
    });
  }

  private readonly parser: SorobanEventParser;

  // ---------------------------------------------------------------------------
  // Public API
  // ---------------------------------------------------------------------------

  /**
   * Index all contract events in [fromLedger, toLedger].
   *
   * @param contractId  Soroban contract address.
   * @param fromLedger  Inclusive start ledger.
   * @param toLedger    Inclusive end ledger.
   * @param force       When true, ignore the stored checkpoint and reindex the
   *                    full range (reconciliation mode). Idempotency prevents
   *                    duplicate records.
   */
  async indexLedgerRange(
    contractId: string,
    fromLedger: number,
    toLedger: number,
    force = false,
  ): Promise<LedgerRangeResult> {
    const effectiveFrom = force
      ? fromLedger
      : await this.resolveStartLedger(contractId, fromLedger);

    if (effectiveFrom > toLedger) {
      this.logger.log(
        `Contract ${contractId}: ledger range [${effectiveFrom}, ${toLedger}] already indexed; skipping.`,
      );
      return { fromLedger, toLedger, processed: 0, persisted: 0, skippedUnknownSchema: 0 };
    }

    this.logger.log(
      `Indexing contract ${contractId} ledgers [${effectiveFrom}, ${toLedger}]${force ? " (force reindex)" : ""}`,
    );

    let processed = 0;
    let persisted = 0;
    let skippedUnknownSchema = 0;
    let cursor: string | undefined;

    // Paginate through Horizon until we've consumed the full range.
    while (true) {
      const { records, nextCursor } = await this.fetchPage(contractId, effectiveFrom, toLedger, cursor);

      if (records.length === 0) break;

      for (const raw of records) {
        processed++;
        const event = this.parser.parse(raw);

        if (!event) {
          // Count schema-version skips separately from parse errors.
          // The parser already logged the reason.
          skippedUnknownSchema++;
          continue;
        }

        await this.persistEvent(event);
        persisted++;
        this.eventEmitter.emit(`stellar.${event.eventType}`, event);
      }

      // Advance checkpoint after each page so a crash mid-range is recoverable.
      const lastRecord = records[records.length - 1];
      if (lastRecord) {
        await this.checkpointRepo.saveLastLedger(contractId, lastRecord.ledger);
      }

      if (!nextCursor || records.length < PAGE_LIMIT) break;
      cursor = nextCursor;
    }

    // Final checkpoint at toLedger once the range is fully consumed.
    await this.checkpointRepo.saveLastLedger(contractId, toLedger);

    this.logger.log(
      `Indexed contract ${contractId} [${effectiveFrom}, ${toLedger}]: ` +
        `processed=${processed} persisted=${persisted} skippedUnknownSchema=${skippedUnknownSchema}`,
    );

    return { fromLedger: effectiveFrom, toLedger, processed, persisted, skippedUnknownSchema };
  }

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  /**
   * Returns the ledger to start from, taking the stored checkpoint into account.
   * If a checkpoint exists and is ahead of `fromLedger`, we resume from checkpoint+1.
   */
  private async resolveStartLedger(contractId: string, fromLedger: number): Promise<number> {
    const last = await this.checkpointRepo.getLastLedger(contractId);
    if (last !== null && last >= fromLedger) {
      return last + 1;
    }
    return fromLedger;
  }

  /**
   * Fetches one page of contract events from Horizon for the given ledger range.
   * Uses the `start_ledger` + `end_ledger` query params (Horizon v2 API).
   */
  private async fetchPage(
    contractId: string,
    fromLedger: number,
    toLedger: number,
    cursor?: string,
  ): Promise<{ records: RawHorizonContractEvent[]; nextCursor: string | undefined }> {
    const url = new URL(`${this.horizonUrl}/contract_events`);
    url.searchParams.set("contract_id", contractId);
    url.searchParams.set("start_ledger", String(fromLedger));
    url.searchParams.set("end_ledger", String(toLedger));
    url.searchParams.set("limit", String(PAGE_LIMIT));
    url.searchParams.set("order", "asc");
    if (cursor) url.searchParams.set("cursor", cursor);

    const res = await fetch(url.toString(), {
      headers: { Accept: "application/json" },
    });

    if (!res.ok) {
      throw new Error(`Horizon returned ${res.status} for ${url.toString()}`);
    }

    // Horizon HAL response: { _embedded: { records: [...] }, _links: { next: { href } } }
    const body = (await res.json()) as {
      _embedded?: { records?: RawHorizonContractEvent[] };
      _links?: { next?: { href?: string } };
    };

    const records = body._embedded?.records ?? [];
    const nextHref = body._links?.next?.href;
    const nextCursor = nextHref
      ? new URL(nextHref).searchParams.get("cursor") ?? undefined
      : undefined;

    return { records, nextCursor };
  }

  private async persistEvent(event: QuickExContractEvent): Promise<void> {
    switch (event.eventType) {
      case "EscrowDeposited":
      case "EscrowWithdrawn":
      case "EscrowRefunded":
        await this.escrowRepo.upsertEvent(event as EscrowEvent);
        break;
      case "PrivacyToggled":
        await this.privacyRepo.upsertEvent(event);
        break;
      case "ContractPaused":
      case "AdminChanged":
      case "ContractUpgraded":
        await this.adminRepo.upsertEvent(event as AdminEvent);
        break;
      case "EphemeralKeyRegistered":
      case "StealthWithdrawn":
        await this.stealthRepo.upsertEvent(event as StealthEvent);
        break;
      default:
        this.logger.debug(`Event ${(event as QuickExContractEvent).eventType} not persisted.`);
    }
  }
}
