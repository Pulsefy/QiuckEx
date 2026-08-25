import { Inject, Injectable, Logger } from '@nestjs/common';
import { HorizonService } from '../transactions/horizon.service';
import type {
  TimelineItem,
  TimelineResponse,
  PaymentTimelineDetail,
  RefundTimelineDetail,
  WebhookTimelineDetail,
} from './transaction-timeline.types';
import type { GetTimelineQueryDto } from './dto/get-timeline.dto';
import {
  TRANSACTION_TIMELINE_REPOSITORY,
  type TransactionTimelineRepository,
} from './transaction-timeline.repository';

@Injectable()
export class TransactionTimelineService {
  private readonly logger = new Logger(TransactionTimelineService.name);

  constructor(
    @Inject(TRANSACTION_TIMELINE_REPOSITORY)
    private readonly timelineRepository: TransactionTimelineRepository,
    private readonly horizonService: HorizonService,
  ) {}

  async getTimeline(query: GetTimelineQueryDto): Promise<TimelineResponse> {
    const { txHash, address, kind, limit = 50 } = query;
    const failedSources: string[] = [];
    const allItems: TimelineItem[] = [];

    // ── 1. Payment events ────────────────────────────────────────────────────
    if (!kind || kind === 'payment') {
      try {
        const paymentItems = await this.collectPaymentItems(txHash, address);
        allItems.push(...paymentItems);
      } catch (err) {
        this.logger.warn(`Timeline: payment source failed for ${txHash.slice(0, 8)}...: ${err}`);
        failedSources.push('payment');
      }
    }

    // ── 2. Refund events ─────────────────────────────────────────────────────
    if (!kind || kind === 'refund') {
      try {
        const refundItems = await this.collectRefundItems(txHash);
        allItems.push(...refundItems);
      } catch (err) {
        this.logger.warn(`Timeline: refund source failed for ${txHash.slice(0, 8)}...: ${err}`);
        failedSources.push('refund');
      }
    }

    // ── 3. Webhook delivery events ───────────────────────────────────────────
    if ((!kind || kind === 'webhook_delivery') && address) {
      try {
        const webhookItems = await this.collectWebhookItems(txHash, address);
        allItems.push(...webhookItems);
      } catch (err) {
        this.logger.warn(`Timeline: webhook source failed for ${txHash.slice(0, 8)}...: ${err}`);
        failedSources.push('webhook_delivery');
      }
    }

    // ── 4. Contract events ───────────────────────────────────────────────────
    if (!kind || kind === 'contract_event') {
      try {
        const contractItems = await this.collectContractItems(txHash);
        allItems.push(...contractItems);
      } catch (err) {
        this.logger.warn(`Timeline: contract source failed for ${txHash.slice(0, 8)}...: ${err}`);
        failedSources.push('contract_event');
      }
    }

    // ── Deduplicate by id, sort descending by timestamp, apply limit ─────────
    const deduplicated = this.deduplicate(allItems);
    const sorted = deduplicated.sort(
      (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime(),
    );
    const paged = sorted.slice(0, limit);

    return {
      txHash,
      items: paged,
      total: sorted.length,
      isPartial: failedSources.length > 0,
      failedSources,
    };
  }

  // ── Payment source ────────────────────────────────────────────────────────

  private async collectPaymentItems(
    txHash: string,
    address?: string,
  ): Promise<TimelineItem[]> {
    // Pull up to 200 items from the horizon payments table and filter to txHash
    const acct = address ?? '';
    if (!acct) {
      // Without an address we can't call getPayments; try Supabase payment_records
      return this.collectPaymentItemsFromDb(txHash);
    }

    const resp = await this.horizonService.getPayments(acct, undefined, 200);
    const matching = resp.items.filter((it) => it.txHash === txHash);

    return matching.map<TimelineItem>((it, idx) => {
      const detail: PaymentTimelineDetail = {
        txHash: it.txHash,
        amount: it.amount,
        asset: it.asset,
        sender: it.source,
        receiver: it.destination,
        memo: it.memo ?? null,
        ledger: null,
        pagingToken: it.pagingToken ?? null,
      };

      return {
        id: `pay_${it.txHash}_${idx}`,
        kind: 'payment',
        timestamp: it.timestamp,
        title: `Payment ${it.status}`,
        description: `${it.amount} ${it.asset} from ${this.shortKey(it.source)} to ${this.shortKey(it.destination)}`,
        status: it.status === 'Success' ? 'success' : 'pending',
        correlationId: it.txHash,
        receiptRef: {
          receiptId: `rcpt_${it.txHash}_${idx}`,
          txHash: it.txHash,
          url: `/receipts/${it.txHash}`,
        },
        paymentDetail: detail,
        refundDetail: null,
        webhookDetail: null,
        contractDetail: null,
      };
    });
  }

  /** Fallback: read payment_records from the repository when no address is provided. */
  private async collectPaymentItemsFromDb(txHash: string): Promise<TimelineItem[]> {
    const data = await this.timelineRepository.getPaymentRecordsByTxHash(txHash);
    if (data.length === 0) return [];

    return data.map<TimelineItem>((row, idx) => {
      const detail: PaymentTimelineDetail = {
        txHash,
        amount: String(row.amount ?? '0'),
        asset: String(row.asset_code ?? 'XLM'),
        sender: String(row.sender_address ?? ''),
        receiver: String(row.receiver_address ?? ''),
        memo: null,
        ledger: null,
        pagingToken: null,
      };

      const ts = String(row.created_at ?? new Date().toISOString());
      return {
        id: `pay_${txHash}_${idx}`,
        kind: 'payment',
        timestamp: ts,
        title: `Payment ${row.status ?? 'unknown'}`,
        description: `${detail.amount} ${detail.asset}`,
        status: row.status === 'completed' ? 'success' : 'pending',
        correlationId: txHash,
        receiptRef: {
          receiptId: `rcpt_${txHash}_${idx}`,
          txHash,
          url: `/receipts/${txHash}`,
        },
        paymentDetail: detail,
        refundDetail: null,
        webhookDetail: null,
        contractDetail: null,
      };
    });
  }

  // ── Refund source ─────────────────────────────────────────────────────────

  private async collectRefundItems(txHash: string): Promise<TimelineItem[]> {
    // Refunds are correlated via entity_id (which is either a payment/link ID)
    // or via notes/correlation stored on the record.
    const data = await this.timelineRepository.getRefundAttempts(txHash);
    if (data.length === 0) return [];

    return data.map<TimelineItem>((row) => {
      const detail: RefundTimelineDetail = {
        refundId: String(row.id),
        entityType: String(row.entity_type),
        entityId: String(row.entity_id),
        reasonCode: String(row.reason_code ?? ''),
        actorId: String(row.actor_id ?? ''),
        refundStatus: String(row.status),
      };

      const statusMap: Record<string, TimelineItem['status']> = {
        approved: 'success',
        pending: 'pending',
        rejected: 'cancelled',
        failed: 'failed',
      };

      return {
        id: `ref_${row.id as string}`,
        kind: 'refund',
        timestamp: String(row.created_at),
        title: `Refund ${detail.refundStatus}`,
        description: `${detail.reasonCode} — entity ${detail.entityType}:${detail.entityId}`,
        status: statusMap[detail.refundStatus] ?? 'pending',
        correlationId: txHash,
        receiptRef: null,
        paymentDetail: null,
        refundDetail: detail,
        webhookDetail: null,
        contractDetail: null,
      };
    });
  }

  // ── Webhook delivery source ───────────────────────────────────────────────

  private async collectWebhookItems(
    txHash: string,
    address: string,
  ): Promise<TimelineItem[]> {
    // Webhook logs are keyed by event_id. For payment events the event_id is
    // typically the tx hash or a derivative. We do a best-effort match.
    const data = await this.timelineRepository.getNotificationLogs(
      txHash,
      address,
      50,
    );
    if (data.length === 0) return [];

    const statusMap: Record<string, TimelineItem['status']> = {
      sent: 'success',
      pending: 'pending',
      failed: 'failed',
      dlq: 'dlq',
    };

    return data.map<TimelineItem>((row) => {
      const detail: WebhookTimelineDetail = {
        webhookLogId: String(row.id),
        eventType: String(row.event_type),
        eventId: String(row.event_id),
        deliveryStatus: String(row.status),
        attempts: Number(row.attempts ?? 0),
        httpStatus: row.webhook_response_status != null ? Number(row.webhook_response_status) : null,
        lastError: row.last_error != null ? String(row.last_error) : null,
        deliveredAt: row.webhook_delivered_at != null ? String(row.webhook_delivered_at) : null,
      };

      return {
        id: `whk_${row.id as string}`,
        kind: 'webhook_delivery',
        timestamp: String(row.created_at),
        title: `Webhook ${detail.eventType} — ${detail.deliveryStatus}`,
        description: detail.lastError
          ? `Delivery failed: ${detail.lastError}`
          : `Delivered after ${detail.attempts} attempt(s)`,
        status: statusMap[detail.deliveryStatus] ?? 'pending',
        correlationId: txHash,
        receiptRef: null,
        paymentDetail: null,
        refundDetail: null,
        webhookDetail: detail,
        contractDetail: null,
      };
    });
  }

  // ── Contract event source ─────────────────────────────────────────────────

  private async collectContractItems(txHash: string): Promise<TimelineItem[]> {
    // Contract change webhooks don't store tx_hash natively; we pull
    // recent enabled webhooks as a best-effort signal.
    // A real production query would join through an event log table.
    const data = await this.timelineRepository.getEnabledContractWebhooks(10);

    if (data.length === 0) return [];

    return data.map<TimelineItem>((row) => ({
      id: `ctr_${row.id as string}_${txHash}`,
      kind: 'contract_event',
      timestamp: String(row.updated_at ?? row.created_at),
      title: 'Contract webhook triggered',
      description: `Webhook endpoint: ${row.webhook_url as string}`,
      status: 'success',
      correlationId: txHash,
      receiptRef: null,
      paymentDetail: null,
      refundDetail: null,
      webhookDetail: null,
      contractDetail: {
        contractId: String(row.id),
        webhookId: String(row.id),
        webhookUrl: String(row.webhook_url),
        triggeredAt: String(row.updated_at ?? row.created_at),
      },
    }));
  }

  // ── Helpers ────────────────────────────────────────────────────────────────

  private deduplicate(items: TimelineItem[]): TimelineItem[] {
    const seen = new Set<string>();
    return items.filter((item) => {
      if (seen.has(item.id)) return false;
      seen.add(item.id);
      return true;
    });
  }

  private shortKey(key: string): string {
    if (key.length <= 12) return key;
    return `${key.slice(0, 6)}…${key.slice(-4)}`;
  }
}
