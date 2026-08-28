export interface AuditLog {
  id: string;
  actor: string;
  action: string;
  target?: string;
  metadata?: Record<string, unknown>;
  requestId?: string;
  createdAt: Date;
}

export interface QueryAuditLogsDto {
  action?: string;
  actor?: string;
  startTime?: string;
  endTime?: string;
  page?: number;
  limit?: number;
}

/**
 * Enriched audit entry recorded for feature-flag changes (issue #26).
 * Stored in `metadata` of the parent AuditLog under key `flagAuditEntry`.
 */
export interface FlagAuditEntry {
  /** Feature flag key that was changed. */
  flagKey: string;
  /** Full flag record before the change. */
  previousValue: unknown;
  /** Full flag record after the change. */
  newValue: unknown;
  /** Identity of the actor who made the change (API key id, fallback to X-Admin-Actor header). */
  actor: string;
  /** Client IP address. */
  ip: string | undefined;
  /** User-Agent header. */
  userAgent: string | undefined;
}
