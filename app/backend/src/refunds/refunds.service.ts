import {
  Injectable,
  Logger,
  ConflictException,
  NotFoundException,
} from '@nestjs/common';
import { SupabaseService } from '../supabase/supabase.service';
import {
  RefundAttemptRecord,
  RefundReasonCode,
  RefundableEntityType,
} from './refunds.types';
import { InitiateRefundDto } from './dto/initiate-refund.dto';
import {
  isPaymentRefundable,
  isEscrowRefundable,
  isLinkRefundable,
} from './refunds.eligibility';

@Injectable()
export class RefundsService {
  private readonly logger = new Logger(RefundsService.name);

  constructor(private readonly supabaseService: SupabaseService) {}

  async initiateRefund(
    dto: InitiateRefundDto,
    actorId: string,
  ): Promise<RefundAttemptRecord> {
    const client = this.supabaseService.getClient();

    // --- Idempotency check ---
    const existing = await this.getRefundByIdempotencyKey(dto.idempotencyKey);
    if (existing) {
      this.logger.log(
        `Idempotent refund hit for key=${dto.idempotencyKey} id=${existing.id}`,
      );
      return existing;
    }

    // --- Eligibility check ---
    await this.assertEligible(dto.entityType, dto.entityId);

    // --- Persist attempt ---
    const { data, error } = await client
      .from('refund_attempts')
      .insert({
        idempotency_key: dto.idempotencyKey,
        entity_type: dto.entityType,
        entity_id: dto.entityId,
        reason_code: dto.reasonCode,
        notes: dto.notes ?? null,
        status: 'pending',
        actor_id: actorId,
      })
      .select()
      .single();

    if (error) {
      // Race: another request already inserted with the same key
      if (error.code === '23505') {
        const race = await this.getRefundByIdempotencyKey(dto.idempotencyKey);
        if (race) return race;
      }
      throw error;
    }

    const record = data as RefundAttemptRecord;

    // --- Audit log ---
    await this.appendAudit(record.id, actorId, 'initiated', dto.reasonCode, dto.notes);

    this.logger.log(`Refund initiated id=${record.id} entity=${dto.entityType}:${dto.entityId}`);
    return record;
  }

  async approveRefund(id: string, actorId: string): Promise<RefundAttemptRecord> {
    const record = await this.getRefundById(id);

    if (record.status !== 'pending') {
      throw new ConflictException({
        error: 'REFUND_NOT_PENDING',
        message: `Refund ${id} is already ${record.status}`,
      });
    }

    const client = this.supabaseService.getClient();
    const { data, error } = await client
      .from('refund_attempts')
      .update({ status: 'approved', updated_at: new Date().toISOString() })
      .eq('id', id)
      .select()
      .single();

    if (error) throw error;

    await this.appendAudit(id, actorId, 'approved', null, null);
    this.logger.log(`Refund approved id=${id}`);
    return data as RefundAttemptRecord;
  }

  async rejectRefund(
    id: string,
    actorId: string,
    notes?: string,
  ): Promise<RefundAttemptRecord> {
    const record = await this.getRefundById(id);

    if (record.status !== 'pending') {
      throw new ConflictException({
        error: 'REFUND_NOT_PENDING',
        message: `Refund ${id} is already ${record.status}`,
      });
    }

    const client = this.supabaseService.getClient();
    const { data, error } = await client
      .from('refund_attempts')
      .update({ status: 'rejected', updated_at: new Date().toISOString() })
      .eq('id', id)
      .select()
      .single();

    if (error) throw error;

    await this.appendAudit(id, actorId, 'rejected', null, notes ?? null);
    this.logger.log(`Refund rejected id=${id}`);
    return data as RefundAttemptRecord;
  }

  async listRefunds(
    cursor?: string,
    limit: number = 20,
  ): Promise<{ data: RefundAttemptRecord[]; next_cursor: string | null; has_more: boolean }> {
    const client = this.supabaseService.getClient();
    const effectiveLimit = Math.min(100, Math.max(1, limit));

    let query = client
      .from('refund_attempts')
      .select('*')
      .order('created_at', { ascending: false })
      .order('id', { ascending: false });

    // Decode cursor
    if (cursor) {
      try {
        const json = Buffer.from(cursor, 'base64url').toString('utf-8');
        const parsed = JSON.parse(json);
        if (typeof parsed.pk === 'string' && typeof parsed.id === 'string') {
          query = query
            .lt('created_at', parsed.pk)
            .or(`created_at.eq.${parsed.pk},id.lt.${parsed.id}`);
        }
      } catch {
        // invalid cursor – start from beginning
      }
    }

    query = query.limit(effectiveLimit + 1);

    const { data, error } = await query;
    if (error) throw error;

    const rows = (data ?? []) as RefundAttemptRecord[];
    const hasMore = rows.length > effectiveLimit;
    const resultData = hasMore ? rows.slice(0, effectiveLimit) : rows;

    let nextCursor: string | null = null;
    if (hasMore && resultData.length > 0) {
      const last = resultData[resultData.length - 1];
      nextCursor = Buffer.from(
        JSON.stringify({ pk: last.created_at, id: last.id }),
        'utf-8',
      ).toString('base64url');
    }

    return { data: resultData, next_cursor: nextCursor, has_more: hasMore };
  }

  async getRefundByIdempotencyKey(
    key: string,
  ): Promise<RefundAttemptRecord | null> {
    const client = this.supabaseService.getClient();
    const { data, error } = await client
      .from('refund_attempts')
      .select('*')
      .eq('idempotency_key', key)
      .maybeSingle();

    if (error) throw error;
    return data as RefundAttemptRecord | null;
  }

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  private async getRefundById(id: string): Promise<RefundAttemptRecord> {
    const client = this.supabaseService.getClient();
    const { data, error } = await client
      .from('refund_attempts')
      .select('*')
      .eq('id', id)
      .maybeSingle();

    if (error) throw error;
    if (!data) {
      throw new NotFoundException({ error: 'REFUND_NOT_FOUND', message: `Refund ${id} not found` });
    }
    return data as RefundAttemptRecord;
  }

  private async assertEligible(
    entityType: RefundableEntityType,
    entityId: string,
  ): Promise<void> {
    const client = this.supabaseService.getClient();

    if (entityType === 'payment') {
      const { data } = await client
        .from('payment_records')
        .select('status')
        .eq('id', entityId)
        .maybeSingle();

      if (!data || !isPaymentRefundable(data.status)) {
        throw new ConflictException({
          error: 'REFUND_NOT_ELIGIBLE',
          message: `Payment ${entityId} is not in a refundable state (must be 'paid')`,
        });
      }
      return;
    }

    if (entityType === 'escrow') {
      const { data } = await client
        .from('escrow_records')
        .select('status')
        .eq('id', entityId)
        .maybeSingle();

      if (!data || !isEscrowRefundable(data.status)) {
        throw new ConflictException({
          error: 'REFUND_NOT_ELIGIBLE',
          message: `Escrow ${entityId} is not in a refundable state (must be 'active' or 'claimed')`,
        });
      }
      return;
    }

    if (entityType === 'link') {
      const { data } = await client
        .from('payment_links')
        .select('state')
        .eq('id', entityId)
        .maybeSingle();

      if (!data || !isLinkRefundable(data.state)) {
        throw new ConflictException({
          error: 'REFUND_NOT_ELIGIBLE',
          message: `Link ${entityId} is not in a refundable state (must be 'PAID')`,
        });
      }
      return;
    }

    throw new ConflictException({
      error: 'REFUND_NOT_ELIGIBLE',
      message: `Unknown entity type: ${entityType as string}`,
    });
  }

  private async appendAudit(
    refundId: string,
    actorId: string,
    action: string,
    reasonCode: RefundReasonCode | null | undefined,
    notes: string | null | undefined,
  ): Promise<void> {
    const client = this.supabaseService.getClient();
    const { error } = await client.from('refund_audit_log').insert({
      refund_id: refundId,
      actor_id: actorId,
      action,
      reason_code: reasonCode ?? null,
      notes: notes ?? null,
    });

    if (error) {
      this.logger.warn(`Failed to append audit log for refund ${refundId}: ${error.message}`);
    }
  }
}
