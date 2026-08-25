import {
  Injectable,
  OnModuleDestroy,
  OnModuleInit,
} from "@nestjs/common";

import { AppConfigService } from "../../config/app-config.service";

/**
 * Lifecycle state of an idempotency record.
 *
 * PENDING   — a request holding this key is currently executing.
 * COMPLETED — the handler finished; responseBody/statusCode are replayable.
 */
export type IdempotencyRecordStatus = "PENDING" | "COMPLETED";

export interface IdempotencyRecord {
  /** SHA-256 fingerprint of method + URL + body used for conflict detection. */
  fingerprint: string;
  status: IdempotencyRecordStatus;
  /** HTTP status code of the completed response (COMPLETED records only). */
  statusCode?: number;
  /** Serialized response body of the completed request (COMPLETED only). */
  responseBody?: unknown;
  /** Epoch ms after which the key is forgotten (retention window). */
  expiresAt: number;
}

const SWEEP_INTERVAL_MS = 5 * 60 * 1000;

/**
 * In-process store backing `Idempotency-Key` support on mutating payment and
 * link endpoints (BE-109).
 *
 * Keys expire lazily (checked on access) and via a periodic sweep after the
 * configurable retention window (`IDEMPOTENCY_RETENTION_HOURS`). Records live
 * in memory, matching the existing transaction-service idempotency pattern;
 * deployments running multiple instances should back this store with Redis or
 * Postgres in a follow-up.
 */
@Injectable()
export class IdempotencyStore implements OnModuleInit, OnModuleDestroy {
  private readonly records = new Map<string, IdempotencyRecord>();
  private sweepTimer?: NodeJS.Timeout;

  constructor(private readonly appConfig: AppConfigService) {}

  /** Retention window in milliseconds from configuration. */
  get retentionMs(): number {
    return this.appConfig.idempotencyRetentionHours * 60 * 60 * 1000;
  }

  /**
   * Register a request for `key`. Returns the existing record when the key is
   * already present (caller decides between replay and conflict), otherwise
   * marks the key as PENDING and returns undefined. Expired keys are treated
   * as fresh.
   */
  begin(key: string, fingerprint: string): IdempotencyRecord | undefined {
    const existing = this.records.get(key);
    if (existing && existing.expiresAt > Date.now()) {
      return existing;
    }
    // Absent or expired — start a new pending window.
    this.records.set(key, {
      fingerprint,
      status: "PENDING",
      expiresAt: Date.now() + this.retentionMs,
    });
    return undefined;
  }

  /** Mark a PENDING record as COMPLETED and store its replayable response. */
  complete(key: string, statusCode: number, responseBody: unknown): void {
    const existing = this.records.get(key);
    this.records.set(key, {
      // Preserve the original fingerprint even when the pending window
      // expired mid-flight, so later reuse conflicts are still detected.
      fingerprint: existing?.fingerprint ?? "",
      status: "COMPLETED",
      statusCode,
      responseBody,
      expiresAt:
        existing && existing.expiresAt > Date.now()
          ? existing.expiresAt
          : Date.now() + this.retentionMs,
    });
  }

  /**
   * Drop a PENDING record so the client can retry the same key after a
   * failed attempt. COMPLETED records are never removed.
   */
  release(key: string): void {
    const existing = this.records.get(key);
    if (existing && existing.status === "PENDING") {
      this.records.delete(key);
    }
  }

  /** Read a record without side effects (used by tests and diagnostics). */
  peek(key: string): IdempotencyRecord | undefined {
    return this.records.get(key);
  }

  /** Remove every expired record. */
  sweepExpired(): number {
    const now = Date.now();
    let removed = 0;
    for (const [key, record] of this.records) {
      if (record.expiresAt <= now) {
        this.records.delete(key);
        removed += 1;
      }
    }
    return removed;
  }

  size(): number {
    return this.records.size;
  }

  onModuleInit(): void {
    this.sweepTimer = setInterval(
      () => this.sweepExpired(),
      SWEEP_INTERVAL_MS,
    );
    // Do not keep the process alive just for sweeping.
    this.sweepTimer.unref?.();
  }

  onModuleDestroy(): void {
    if (this.sweepTimer) {
      clearInterval(this.sweepTimer);
    }
  }
}
