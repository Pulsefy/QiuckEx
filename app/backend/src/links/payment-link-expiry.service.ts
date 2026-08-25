import { Inject, Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { v4 as uuidv4 } from 'uuid';

import { EventEmitter2 } from '@nestjs/event-emitter';
import { AuditService } from '../audit/audit.service';
import {
  PAYMENT_LINKS_REPOSITORY,
  type PaymentLinksRepository,
} from './payment-links.repository';

@Injectable()
export class PaymentLinkExpiryService {
  private readonly logger = new Logger(PaymentLinkExpiryService.name);

  constructor(
    @Inject(PAYMENT_LINKS_REPOSITORY)
    private readonly paymentLinksRepository: PaymentLinksRepository,
    private readonly eventEmitter: EventEmitter2,
    private readonly auditService: AuditService,
  ) {}

  // Run every minute to sweep expired open links. Idempotent by design.
  @Cron(CronExpression.EVERY_MINUTE, { name: 'payment-link-expiry-sweep', timeZone: 'UTC' })
  async handleCron(): Promise<void> {
    const runId = uuidv4();
    try {
      const count = await this.runExpirySweep(runId);
      if (count > 0) this.logger.log(`Expiry sweep ${runId}: expired ${count} link(s)`);
    } catch (err) {
      this.logger.error(`Expiry sweep ${runId} failed: ${(err as Error).message}`);
    }
  }

  /**
   * Sweep open payment_links whose `expires_at` <= now and mark them expired.
   * The update is constrained to rows with status='open' so it is safe to
   * run concurrently or replayed — idempotent and replay-safe.
   */
  async runExpirySweep(runId: string): Promise<number> {
    const nowIso = new Date().toISOString();
    try {
      const updated = await this.paymentLinksRepository.markExpiredLinks(
        nowIso,
        runId,
      );

      if (updated.length === 0) return 0;

      // For each updated link write an audit row and emit a notification event
      for (const row of updated) {
        const linkId = String(row.id);
        const expiresAt = row.expires_at ? String(row.expires_at) : null;

        // Persist to expiry audit table
        await this.paymentLinksRepository.insertExpiryAudit({
          linkId,
          previousStatus: 'open',
          newStatus: 'expired',
          expiresAt,
          processedAt: nowIso,
          processedBy: 'expiry-worker',
          runId,
          note: 'sweep',
        });

        // Emit an audit log for operators
        await this.auditService.log('system:expiry-worker', 'payment_link.expired', linkId, {
          runId,
          expiresAt,
        });

        // Notify downstream notification service via event-emitter so user gets informed
        this.eventEmitter.emit('payment.link.expired', {
          linkId,
          expiresAt,
          ownerPublicKey: row.owner_public_key ?? null,
          destinationPublicKey: row.destination_public_key ?? null,
        });
      }

      return updated.length;
    } catch (err) {
      this.logger.error(`Expiry sweep failed: ${(err as Error).message}`);
      return 0;
    }
  }
}
