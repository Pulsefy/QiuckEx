import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { v4 as uuidv4 } from 'uuid';

import { AuditService } from '../audit/audit.service';
import { SupabaseService } from '../supabase/supabase.service';
import { BranchPreviewCache } from './branch-preview.cache';
import { BranchPreviewRepository } from './branch-preview.repository';
import { BranchPreviewEnvironment } from './branch-preview.model';
import {
  BRANCH_PREVIEW_AUTO_EXPIRED_EVENT,
  PREVIEW_AUTO_EXPIRY_WORKER_ACTOR,
  resolvePreviewExpiryThresholds,
} from './branch-preview-expiry.config';
import {
  evaluatePreviewAutoExpiry,
  PreviewAutoExpiryReason,
} from './branch-preview-expiry.policy';

@Injectable()
export class BranchPreviewAutoExpiryService {
  private readonly logger = new Logger(BranchPreviewAutoExpiryService.name);
  private readonly thresholds = resolvePreviewExpiryThresholds();

  constructor(
    private readonly repository: BranchPreviewRepository,
    private readonly cache: BranchPreviewCache,
    private readonly auditService: AuditService,
    private readonly supabase: SupabaseService,
    private readonly eventEmitter: EventEmitter2,
  ) {}

  @Cron(CronExpression.EVERY_HOUR, {
    name: 'branch-preview-auto-expiry',
    timeZone: 'UTC',
  })
  async handleCron(): Promise<void> {
    const runId = uuidv4();
    try {
      const count = await this.runAutoExpirySweep(runId);
      if (count > 0) {
        this.logger.log(`Preview auto-expiry ${runId}: deactivated ${count} preview(s)`);
      }
    } catch (err) {
      this.logger.error(`Preview auto-expiry ${runId} failed: ${(err as Error).message}`);
    }
  }

  /**
   * Marks stale previews inactive, records audit rows, and emits cleanup hooks.
   * Idempotent: only active, non-exempt previews are updated.
   */
  async runAutoExpirySweep(runId: string, now: Date = new Date()): Promise<number> {
    const candidates = await this.repository.findActiveForAutoExpiryEvaluation();
    let deactivated = 0;

    for (const preview of candidates) {
      const evaluation = evaluatePreviewAutoExpiry(preview, this.thresholds, now);
      if (!evaluation.shouldExpire || !evaluation.reason) {
        continue;
      }

      const updated = await this.repository.deactivateForAutoExpiry(
        preview.id,
        evaluation.reason,
        now,
      );
      if (!updated) {
        continue;
      }

      this.cache.delete(updated.branchName);
      await this.recordExpiryAudit(updated, evaluation.reason, runId, now);
      await this.auditService.log(
        PREVIEW_AUTO_EXPIRY_WORKER_ACTOR,
        'branch_preview.auto_expired',
        updated.id,
        {
          runId,
          branchName: updated.branchName,
          reason: evaluation.reason,
          lastActivityAt: updated.lastActivityAt?.toISOString() ?? null,
          createdAt: updated.createdAt.toISOString(),
          expiresAt: updated.expiresAt?.toISOString() ?? null,
        },
      );

      this.eventEmitter.emit(BRANCH_PREVIEW_AUTO_EXPIRED_EVENT, {
        previewId: updated.id,
        branchName: updated.branchName,
        reason: evaluation.reason,
        runId,
      });

      deactivated += 1;
      this.logger.log(
        `Auto-expired preview ${updated.branchName} (${evaluation.reason})`,
      );
    }

    return deactivated;
  }

  private async recordExpiryAudit(
    preview: BranchPreviewEnvironment,
    reason: PreviewAutoExpiryReason,
    runId: string,
    now: Date,
  ): Promise<void> {
    const client = this.supabase.getClient();
    const note = this.buildAuditNote(reason);

    try {
      await client.from('branch_preview_expiry_audit').insert({
        preview_id: preview.id,
        branch_name: preview.branchName,
        expiry_reason: reason,
        previous_is_active: true,
        last_activity_at: preview.lastActivityAt?.toISOString() ?? null,
        created_at: preview.createdAt.toISOString(),
        expires_at: preview.expiresAt?.toISOString() ?? null,
        processed_at: now.toISOString(),
        processed_by: PREVIEW_AUTO_EXPIRY_WORKER_ACTOR,
        run_id: runId,
        note,
      });
    } catch (err) {
      this.logger.warn(
        `Failed to persist branch preview expiry audit for ${preview.id}: ${(err as Error).message}`,
      );
    }
  }

  private buildAuditNote(reason: PreviewAutoExpiryReason): string {
    switch (reason) {
      case 'ttl_expired':
        return 'Preview TTL (expires_at) reached';
      case 'inactivity':
        return `No activity for at least ${this.thresholds.inactivityMs}ms`;
      case 'max_age':
        return `Preview age exceeded ${this.thresholds.maxAgeMs}ms`;
      default:
        return 'Auto-expired by scheduled worker';
    }
  }
}
