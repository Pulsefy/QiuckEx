export type AuditLogSource = 'supabase' | 'fallback';

export interface AuditLog {
  id: string;
  actor: string;
  action: string;
  target?: string;
  metadata?: Record<string, unknown>;
  requestId?: string;
  createdAt: Date;
  source: AuditLogSource;
}

export interface QueryAuditLogsDto {
  action?: string;
  actor?: string;
  startTime?: string;
  endTime?: string;
  page?: number;
  limit?: number;
}
