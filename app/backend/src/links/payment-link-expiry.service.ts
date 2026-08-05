import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { v4 as uuidv4 } from 'uuid';

import { SupabaseService } from '../supabase/supabase.service';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { AuditService } from '../audit/audit.service';

@Injectable()
export class PaymentLinkExpiryService {
  private readonly logger = new Logger(PaymentLinkExpiryService.name);

  constructor(
    private readonly supabase: SupabaseService,
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
    const client = this.supabase.getClient();
    const nowIso = new Date().toISOString();
    try {
      // Update matched rows and return their representation so we can audit and emit events.
      const { data, error } = await client
        .from('payment_links')
        .update({
          status: 'expired',
          expiry_processed_at: nowIso,
          expiry_processed_by: 'expiry-worker',
          expiry_note: `expired by sweep ${runId}`,
        })
        .eq('status', 'open')
        .not('expires_at', 'is', null)
        .lte('expires_at', nowIso)
        .select('id,owner_public_key,destination_public_key,amount,asset_code,memo,expires_at,matched_tx_hash,matched_at');

      if (error) {
        this.logger.error(`Failed to mark expired links: ${error.message}`);
        return 0;
      }

      const updated = (data ?? []) as Array<Record<string, unknown>>;
      if (updated.length === 0) return 0;

      // For each updated link write an audit row and emit a notification event
      for (const row of updated) {
        const linkId = String(row.id);
        const expiresAt = row.expires_at ? String(row.expires_at) : null;

        // Persist to expiry audit table
        try {
          await client.from('payment_link_expiry_audit').insert({
            link_id: linkId,
            previous_status: 'open',
            new_status: 'expired',
            expires_at: expiresAt,
            processed_at: nowIso,
            processed_by: 'expiry-worker',
            run_id: runId,
            note: `sweep`,
          });
        } catch (err) {
          this.logger.warn(`Failed to record expiry audit for ${linkId}: ${(err as Error).message}`);
        }

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
