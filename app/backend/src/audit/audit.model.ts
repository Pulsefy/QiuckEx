export interface AuditLog {
  id: string;
  actor: string;
  action: string;
  target?: string;
  metadata?: Record<string, any>;
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
