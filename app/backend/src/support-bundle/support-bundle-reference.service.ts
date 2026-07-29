import { Injectable, Logger, NotFoundException } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { randomUUID } from 'crypto';

import { SupabaseService } from '../supabase/supabase.service';
import { AuditService } from '../audit/audit.service';
import { redactValue } from '../common/utils/redaction.util';
import {
  CreateSupportBundleReferenceDto,
  SupportBundleReferenceResponseDto,
  SupportBundleReferenceTargetType,
} from './dto/support-bundle-reference.dto';
import { SupportBundleReferenceRecord } from './support-bundle-reference.types';

const DEFAULT_TTL_DAYS = 30;
const TABLE_NAME = 'support_bundle_references';

@Injectable()
export class SupportBundleReferenceService {
  private readonly logger = new Logger(SupportBundleReferenceService.name);
  private readonly fallbackStore = new Map<string, SupportBundleReferenceRecord>();

  constructor(
    private readonly supabaseService: SupabaseService,
    private readonly auditService: AuditService,
  ) {}

  async create(
    dto: CreateSupportBundleReferenceDto,
    createdBy: string,
  ): Promise<SupportBundleReferenceResponseDto> {
    const now = new Date();
    const ttlDays = dto.ttlDays ?? DEFAULT_TTL_DAYS;
    const expiresAt = new Date(now.getTime() + ttlDays * 24 * 60 * 60 * 1000);

    const record: SupportBundleReferenceRecord = {
      id: randomUUID(),
      bundleId: dto.bundleId,
      targetType: dto.targetType,
      targetId: dto.targetId,
      createdBy,
      createdAt: now.toISOString(),
      expiresAt: expiresAt.toISOString(),
      redacted: false,
      redactedAt: null,
    };

    await this.persist(record);

    await this.auditService.log(createdBy, 'support_bundle_reference.created', record.id, {
      targetType: record.targetType,
      targetId: record.targetId,
      expiresAt: record.expiresAt,
    });

    return this.toResponseDto(record);
  }

  async findById(id: string): Promise<SupportBundleReferenceResponseDto> {
    const record = await this.readOne(id);

    if (!record || this.isExpiredOrRedacted(record)) {
      throw new NotFoundException(`Support bundle reference ${id} not found`);
    }

    return this.toResponseDto(record);
  }

  async findByTarget(
    targetType: SupportBundleReferenceTargetType,
    targetId: string,
  ): Promise<SupportBundleReferenceResponseDto[]> {
    const records = await this.readAll();

    return records
      .filter((r) => r.targetType === targetType && r.targetId === targetId)
      .filter((r) => !this.isExpiredOrRedacted(r))
      .sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1))
      .map((r) => this.toResponseDto(r));
  }

  async redact(id: string, redactedBy: string): Promise<SupportBundleReferenceResponseDto> {
    const record = await this.readOne(id);
    if (!record) {
      throw new NotFoundException(`Support bundle reference ${id} not found`);
    }

    const now = new Date().toISOString();
    record.redacted = true;
    record.redactedAt = record.redactedAt ?? now;

    await this.persist(record);

    await this.auditService.log(redactedBy, 'support_bundle_reference.redacted', record.id, {
      targetType: record.targetType,
      targetId: record.targetId,
    });

    return this.toResponseDto(record);
  }

  /**
   * Marks references past their expiry as redacted so lookups stop returning them
   * even if a caller bypasses the lazy expiry check in findById/findByTarget.
   */
  @Cron(CronExpression.EVERY_DAY_AT_MIDNIGHT)
  async cleanupExpired(): Promise<number> {
    const now = new Date().toISOString();

    try {
      const client = this.supabaseService.getClient();
      const { data, error } = await client
        .from(TABLE_NAME)
        .update({ redacted: true, redacted_at: now })
        .lt('expires_at', now)
        .eq('redacted', false)
        .select('id');

      if (error) throw error;

      const count = data?.length ?? 0;
      if (count > 0) {
        this.logger.log(`Redacted ${count} expired support bundle references`);
      }
      return count;
    } catch (error) {
      let count = 0;
      for (const record of this.fallbackStore.values()) {
        if (!record.redacted && record.expiresAt < now) {
          record.redacted = true;
          record.redactedAt = now;
          count += 1;
        }
      }
      if (count > 0) {
        this.logger.warn(
          `Supabase unavailable during expiry sweep, redacted ${count} in fallback store: ${
            (error as Error).message
          }`,
        );
      }
      return count;
    }
  }

  private isExpiredOrRedacted(record: SupportBundleReferenceRecord): boolean {
    return record.redacted || record.expiresAt < new Date().toISOString();
  }

  private async persist(record: SupportBundleReferenceRecord): Promise<void> {
    this.fallbackStore.set(record.id, record);

    try {
      const client = this.supabaseService.getClient();
      const { error } = await client.from(TABLE_NAME).upsert({
        id: record.id,
        bundle_id: record.bundleId,
        target_type: record.targetType,
        target_id: record.targetId,
        created_by: record.createdBy,
        created_at: record.createdAt,
        expires_at: record.expiresAt,
        redacted: record.redacted,
        redacted_at: record.redactedAt,
      });
      if (error) throw error;
    } catch (error) {
      this.logger.warn(
        `Failed to persist support bundle reference ${record.id} to Supabase, kept in fallback store only: ${
          (error as Error).message
        }`,
      );
    }
  }

  private async readOne(id: string): Promise<SupportBundleReferenceRecord | null> {
    try {
      const client = this.supabaseService.getClient();
      const { data, error } = await client
        .from(TABLE_NAME)
        .select('*')
        .eq('id', id)
        .maybeSingle();

      if (error) throw error;
      if (data) return this.mapDbToRecord(data);
    } catch (error) {
      this.logger.warn(
        `Falling back to in-memory support bundle reference store: ${(error as Error).message}`,
      );
    }

    return this.fallbackStore.get(id) ?? null;
  }

  private async readAll(): Promise<SupportBundleReferenceRecord[]> {
    const fallback = Array.from(this.fallbackStore.values());

    try {
      const client = this.supabaseService.getClient();
      const { data, error } = await client
        .from(TABLE_NAME)
        .select('*')
        .order('created_at', { ascending: false });

      if (error) throw error;
      if (!data || data.length === 0) return fallback;

      return data.map((row) => this.mapDbToRecord(row));
    } catch (error) {
      this.logger.warn(
        `Falling back to in-memory support bundle reference store: ${(error as Error).message}`,
      );
      return fallback;
    }
  }

  private mapDbToRecord(row: Record<string, unknown>): SupportBundleReferenceRecord {
    return {
      id: String(row.id),
      bundleId: String(row.bundle_id),
      targetType: row.target_type as SupportBundleReferenceTargetType,
      targetId: String(row.target_id),
      createdBy: String(row.created_by),
      createdAt: String(row.created_at),
      expiresAt: String(row.expires_at),
      redacted: Boolean(row.redacted),
      redactedAt: row.redacted_at ? String(row.redacted_at) : null,
    };
  }

  private toResponseDto(record: SupportBundleReferenceRecord): SupportBundleReferenceResponseDto {
    return {
      id: record.id,
      bundleIdMasked: redactValue(record.bundleId),
      targetType: record.targetType,
      targetId: record.targetId,
      createdAt: record.createdAt,
      expiresAt: record.expiresAt,
      redacted: record.redacted,
    };
  }
}
