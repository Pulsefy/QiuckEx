import { Injectable } from "@nestjs/common";

import { IndexerLagService } from "../indexer-lag/indexer-lag.service";
import { AuditService } from "../audit/audit.service";
import { NotificationLogRepository } from "../notifications/notification-log.repository";

@Injectable()
export class OperationsService {
  constructor(
    private readonly indexerLagService: IndexerLagService,
    private readonly auditService: AuditService,
    private readonly notificationLogRepository: NotificationLogRepository,
  ) {}

  async getIndexerStatus() {
    return this.indexerLagService.getStatus();
  }

  async getIngestionStatus() {
    const status = this.indexerLagService.getStatus();

    return {
      currentNetworkLedger: status.currentNetworkLedger,
      lastIndexedLedger: status.lastIndexedLedger,
      lagLedgers: status.lagLedgers,
      isLagging: status.isLagging,
      thresholdLedgers: status.thresholdLedgers,
    };
  }

  async getWebhookBacklog() {
    const retries =
      await this.notificationLogRepository.getPendingRetries(100);

    return {
      totalPending: retries.length,
      backlog: retries,
    };
  }

  async getRecentErrors(page = 1, limit = 50) {
    const result = await this.auditService.query({
      page,
      limit,
    });

    const redacted = result.data.map((entry) => ({
      id: entry.id,
      action: entry.action,
      actor:
        entry.actor && entry.actor.includes("@")
          ? "[REDACTED]"
          : entry.actor,
      requestId: entry.requestId,
      createdAt: entry.createdAt,
    }));

    return {
      total: result.total,
      page: result.page,
      limit: result.limit,
      errors: redacted,
    };
  }
}