import {
  Injectable,
  Logger,
  NotFoundException,
  ServiceUnavailableException,
} from '@nestjs/common';
import { createHash } from 'crypto';

import { AppConfigService } from '../config';
import { AuditService } from '../audit/audit.service';
import { SupabaseService } from '../supabase/supabase.service';
import {
  FeatureFlagEvaluationContext,
  FeatureFlagEvaluationResult,
  FeatureFlagRecord,
  FeatureFlagsListResponse,
  UpdateFeatureFlagDto,
} from './feature-flags.dto';

type CacheState = {
  flags: FeatureFlagRecord[];
  source: 'store' | 'bootstrap' | 'cache';
  storeAvailable: boolean;
  expiresAt: number;
};

const DEFAULT_FLAGS: FeatureFlagRecord[] = [
  {
    key: 'bulk_invoicing_v2',
    name: 'Bulk Invoicing v2',
    description: 'Enables templates, saved customers, and preview flow in bulk invoicing.',
    enabled: true,
    killSwitch: false,
    rolloutPercentage: 100,
    allowedUsers: [],
    environments: ['development', 'test', 'production'],
    metadata: { surface: 'generator' },
    updatedAt: new Date(0).toISOString(),
    updatedBy: 'bootstrap',
  },
  {
    key: 'bulk_link_generation',
    name: 'Bulk Link Generation',
    description: 'Controls new bulk payment-link creation requests.',
    enabled: true,
    killSwitch: false,
    rolloutPercentage: 100,
    allowedUsers: [],
    environments: ['development', 'test', 'production'],
    metadata: { surface: 'links/bulk', riskyAction: true },
    updatedAt: new Date(0).toISOString(),
    updatedBy: 'bootstrap',
  },
];

@Injectable()
export class FeatureFlagsService {
  private readonly logger = new Logger(FeatureFlagsService.name);
  private cache: CacheState | null = null;

  constructor(
    private readonly supabaseService: SupabaseService,
    private readonly configService: AppConfigService,
    private readonly auditService: AuditService,
  ) {}

  async listFlags(): Promise<FeatureFlagsListResponse> {
    const snapshot = await this.loadFlags();
    return {
      flags: snapshot.flags,
      source: snapshot.source,
      storeAvailable: snapshot.storeAvailable,
    };
  }

  async getFlagOrThrow(key: string): Promise<FeatureFlagRecord> {
    const { flags } = await this.loadFlags();
    const flag = flags.find((entry) => entry.key === key);
    if (!flag) {
      throw new NotFoundException(`Feature flag "${key}" not found`);
    }
    return flag;
  }

  async evaluateFlag(
    key: string,
    context: FeatureFlagEvaluationContext = {},
  ): Promise<FeatureFlagEvaluationResult> {
    const snapshot = await this.loadFlags();
    const flag = snapshot.flags.find((entry) => entry.key === key);

    if (!flag) {
      return {
        key,
        enabled: false,
        reason: 'missing-flag',
        source: snapshot.source,
      };
    }

    const environment = (context.environment ?? this.configService.nodeEnv).toLowerCase();
    const allowedEnvironments = flag.environments.map((value) => value.toLowerCase());

    if (flag.killSwitch) {
      return { key, enabled: false, reason: 'kill-switch', source: snapshot.source };
    }

    if (!flag.enabled) {
      return { key, enabled: false, reason: 'disabled', source: snapshot.source };
    }

    if (allowedEnvironments.length > 0 && !allowedEnvironments.includes(environment)) {
      return {
        key,
        enabled: false,
        reason: 'environment-mismatch',
        source: snapshot.source,
      };
    }

    const normalizedUserId = context.userId?.trim();
    if (normalizedUserId && flag.allowedUsers.includes(normalizedUserId)) {
      return {
        key,
        enabled: true,
        reason: 'allowlist-match',
        source: snapshot.source,
      };
    }

    if (flag.rolloutPercentage >= 100) {
      return { key, enabled: true, reason: 'enabled', source: snapshot.source };
    }

    if (flag.rolloutPercentage <= 0) {
      return { key, enabled: false, reason: 'rollout-miss', source: snapshot.source };
    }

    if (!normalizedUserId) {
      return {
        key,
        enabled: false,
        reason: 'missing-user-context',
        source: snapshot.source,
      };
    }

    const bucket = this.computeRolloutBucket(key, normalizedUserId);
    const enabled = bucket < flag.rolloutPercentage;
    return {
      key,
      enabled,
      reason: enabled ? 'rollout-match' : 'rollout-miss',
      source: snapshot.source,
    };
  }

  async assertActionEnabled(
    key: string,
    context: FeatureFlagEvaluationContext = {},
  ): Promise<void> {
    const evaluation = await this.evaluateFlag(key, context);
    if (!evaluation.enabled) {
      throw new ServiceUnavailableException({
        error: 'FEATURE_DISABLED',
        flag: key,
        reason: evaluation.reason,
        message: `Feature flag "${key}" is currently blocking this write action.`,
      });
    }
  }

  async updateFlag(
    key: string,
    patch: UpdateFeatureFlagDto,
    actor: string,
  ): Promise<FeatureFlagRecord> {
    const current = await this.getFlagOrThrow(key);
    const next: FeatureFlagRecord = {
      ...current,
      ...patch,
      allowedUsers: patch.allowedUsers?.map((value) => value.trim()).filter(Boolean) ?? current.allowedUsers,
      environments: patch.environments?.map((value) => value.trim()).filter(Boolean) ?? current.environments,
      metadata: patch.metadata ?? current.metadata,
      updatedAt: new Date().toISOString(),
      updatedBy: actor,
    };

    try {
      const client = this.supabaseService.getClient();
      const { data, error } = await client
        .from('feature_flags')
        .upsert({
          key: next.key,
          name: next.name,
          description: next.description,
          enabled: next.enabled,
          kill_switch: next.killSwitch,
          rollout_percentage: next.rolloutPercentage,
          allowed_users: next.allowedUsers,
          environments: next.environments,
          metadata: next.metadata,
          updated_at: next.updatedAt,
          updated_by: next.updatedBy,
        })
        .select()
        .single();

      if (error) {
        throw error;
      }

      const persisted = this.mapRowToFlag(data);
      this.cache = {
        flags: this.upsertFlagInCollection((await this.loadFlags()).flags, persisted),
        source: 'store',
        storeAvailable: true,
        expiresAt: Date.now() + this.configService.featureFlagsCacheTtlMs,
      };

      await this.auditService.log(
        actor,
        'feature_flag.updated',
        key,
        {
          before: current,
          after: persisted,
        },
      );

      return persisted;
    } catch (error) {
      this.logger.warn(
        `Feature flag store unavailable during update for ${key}: ${(error as Error).message}`,
      );
      throw new ServiceUnavailableException({
        error: 'FEATURE_FLAG_STORE_UNAVAILABLE',
        message: 'Feature flag store is unavailable; safe defaults remain active.',
      });
    }
  }

  async getOperationalState(): Promise<{ source: string; storeAvailable: boolean; cacheExpiresAt: number | null }> {
    const snapshot = await this.loadFlags();
    return {
      source: snapshot.source,
      storeAvailable: snapshot.storeAvailable,
      cacheExpiresAt: this.cache?.expiresAt ?? null,
    };
  }

  private async loadFlags(): Promise<CacheState> {
    if (this.cache && this.cache.expiresAt > Date.now()) {
      return { ...this.cache, source: this.cache.source === 'store' ? 'cache' : this.cache.source };
    }

    const bootstrapFlags = this.getBootstrapFlags();

    try {
      const client = this.supabaseService.getClient();
      const { data, error } = await client.from('feature_flags').select('*').order('key');
      if (error) {
        throw error;
      }

      const storedFlags = (data ?? []).map((row) => this.mapRowToFlag(row));
      const mergedFlags = this.mergeFlags(bootstrapFlags, storedFlags);
      this.cache = {
        flags: mergedFlags,
        source: 'store',
        storeAvailable: true,
        expiresAt: Date.now() + this.configService.featureFlagsCacheTtlMs,
      };
      return this.cache;
    } catch (error) {
      this.logger.warn(
        `Falling back to bootstrap feature flags: ${(error as Error).message}`,
      );
      this.cache = {
        flags: bootstrapFlags,
        source: 'bootstrap',
        storeAvailable: false,
        expiresAt: Date.now() + this.configService.featureFlagsCacheTtlMs,
      };
      return this.cache;
    }
  }

  private getBootstrapFlags(): FeatureFlagRecord[] {
    const raw = this.configService.featureFlagsBootstrapJson;
    if (!raw) {
      return DEFAULT_FLAGS.map((flag) => ({ ...flag }));
    }

    try {
      const parsed = JSON.parse(raw) as Array<Partial<FeatureFlagRecord> & { key: string }>;
      return this.mergeFlags(
        DEFAULT_FLAGS,
        parsed.map((entry) => ({
          key: entry.key,
          name: entry.name ?? entry.key,
          description: entry.description ?? '',
          enabled: entry.enabled ?? false,
          killSwitch: entry.killSwitch ?? false,
          rolloutPercentage: this.normalizeRollout(entry.rolloutPercentage),
          allowedUsers: entry.allowedUsers ?? [],
          environments: entry.environments ?? [],
          metadata: entry.metadata ?? {},
          updatedAt: entry.updatedAt ?? new Date(0).toISOString(),
          updatedBy: entry.updatedBy ?? 'bootstrap',
        })),
      );
    } catch (error) {
      this.logger.warn(
        `Invalid FEATURE_FLAGS_BOOTSTRAP_JSON; using defaults: ${(error as Error).message}`,
      );
      return DEFAULT_FLAGS.map((flag) => ({ ...flag }));
    }
  }

  private mergeFlags(
    bootstrapFlags: FeatureFlagRecord[],
    storedFlags: FeatureFlagRecord[],
  ): FeatureFlagRecord[] {
    const index = new Map<string, FeatureFlagRecord>();
    for (const flag of bootstrapFlags) {
      index.set(flag.key, { ...flag });
    }
    for (const flag of storedFlags) {
      index.set(flag.key, { ...flag });
    }
    return Array.from(index.values()).sort((left, right) => left.key.localeCompare(right.key));
  }

  private mapRowToFlag(row: Record<string, unknown>): FeatureFlagRecord {
    return {
      key: String(row.key),
      name: String(row.name ?? row.key),
      description: String(row.description ?? ''),
      enabled: Boolean(row.enabled),
      killSwitch: Boolean(row.kill_switch),
      rolloutPercentage: this.normalizeRollout(row.rollout_percentage),
      allowedUsers: Array.isArray(row.allowed_users)
        ? row.allowed_users.map((value) => String(value))
        : [],
      environments: Array.isArray(row.environments)
        ? row.environments.map((value) => String(value))
        : [],
      metadata:
        row.metadata && typeof row.metadata === 'object'
          ? (row.metadata as Record<string, unknown>)
          : {},
      updatedAt: String(row.updated_at ?? new Date(0).toISOString()),
      updatedBy: String(row.updated_by ?? 'system'),
    };
  }

  private upsertFlagInCollection(
    flags: FeatureFlagRecord[],
    next: FeatureFlagRecord,
  ): FeatureFlagRecord[] {
    const remaining = flags.filter((flag) => flag.key !== next.key);
    remaining.push(next);
    return remaining.sort((left, right) => left.key.localeCompare(right.key));
  }

  private computeRolloutBucket(key: string, userId: string): number {
    const hash = createHash('sha256').update(`${key}:${userId}`).digest('hex');
    return parseInt(hash.slice(0, 8), 16) % 100;
  }

  private normalizeRollout(value: unknown): number {
    const numeric = Number(value);
    if (Number.isNaN(numeric)) {
      return 0;
    }
    return Math.max(0, Math.min(100, numeric));
  }
}
