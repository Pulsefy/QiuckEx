import { Injectable, Logger } from '@nestjs/common';
import { AuditLog, QueryAuditLogsDto } from './audit.model';
import { randomUUID } from 'crypto';

@Injectable()
export class AuditService {
  private readonly logger = new Logger(AuditService.name);
  // In-memory store for minimal implementation
  private logs: AuditLog[] = [];

  log(actor: string, action: string, target?: string, metadata?: Record<string, any>, requestId?: string) {
    const entry: AuditLog = {
      id: randomUUID(),
      actor,
      action,
      target,
      metadata,
      requestId,
      createdAt: new Date(),
    };
    this.logs.push(entry);
    this.logger.log(`Audit Event: ${action} by ${actor}`);
  }

  query(dto: QueryAuditLogsDto) {
    let result = this.logs;

    if (dto.action) {
      result = result.filter(log => log.action === dto.action);
    }
    if (dto.actor) {
      result = result.filter(log => log.actor === dto.actor);
    }
    if (dto.startTime) {
      const start = new Date(dto.startTime).getTime();
      result = result.filter(log => log.createdAt.getTime() >= start);
    }
    if (dto.endTime) {
      const end = new Date(dto.endTime).getTime();
      result = result.filter(log => log.createdAt.getTime() <= end);
    }

    // Pagination
    const page = Number(dto.page) || 1;
    const limit = Number(dto.limit) || 50;
    const startIndex = (page - 1) * limit;
    const paginated = result.slice(startIndex, startIndex + limit);

    return {
      data: paginated,
      total: result.length,
      page,
      limit,
    };
  }

  exportCsv(): string {
    if (this.logs.length === 0) return 'id,actor,action,target,requestId,createdAt\n';
    
    const header = 'id,actor,action,target,requestId,createdAt\n';
    const rows = this.logs.map(log => {
      return `${log.id},${log.actor},${log.action},${log.target || ''},${log.requestId || ''},${log.createdAt.toISOString()}`;
    }).join('\n');
    
    return header + rows;
  }

  applyRetention(days: number = 90) {
    const cutoff = new Date();
    cutoff.setDate(cutoff.getDate() - days);
    
    const initialCount = this.logs.length;
    this.logs = this.logs.filter(log => log.createdAt > cutoff);
    const deletedCount = initialCount - this.logs.length;
    
    this.logger.log(`Applied retention policy: deleted ${deletedCount} logs older than ${days} days`);
    return { deletedCount };
  }
}
