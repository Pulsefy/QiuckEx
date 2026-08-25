import { BadRequestException, Injectable, Logger } from '@nestjs/common';
import { createHash } from 'crypto';

import { AuditService } from '../audit/audit.service';
import { SupabaseService } from '../supabase/supabase.service';
import {
  DATA_RETENTION_POLICIES,
  PrivacySubjectKey,
  RetentionPolicy,
  SubjectIdentifier,
} from './data-retention.policy';

export interface ErasureSubject {
  publicKey?: string;
  username?: string;
  userId?: string;
}

export interface StoreRetentionResult {
  storeKey: string;
  tableName: string;
  action: 'delete' | 'anonymize';
  affectedRows: number;
  error?: string;
}

export interface PrivacyWorkflowResult {
  runAt: string;
  results: StoreRetentionResult[];
}

type QueryBuilder = {
  delete?: () => QueryBuilder;
  update?: (values: Record<string, unknown>) => QueryBuilder;
  eq?: (column: string, value: unknown) => QueryBuilder;
  lt?: (column: string, value: unknown) => QueryBuilder;
  select?: (columns?: string) => Promise<{ data?: unknown[] | null; error?: { message?: string } | null }>;
};

@Injectable()
export class PrivacyRetentionService {
  private readonly logger = new Logger(PrivacyRetentionService.name);

  constructor(
    private readonly supabaseService: SupabaseService,
    private readonly auditService: AuditService,
  ) {}

  getPolicies(): readonly RetentionPolicy[] {
    return DATA_RETENTION_POLICIES;
  }

  async enforceRetention(now = new Date()): Promise<PrivacyWorkflowResult> {
    const runAt = now.toISOString();
    const results: StoreRetentionResult[] = [];

    for (const policy of DATA_RETENTION_POLICIES) {
      results.push(await this.enforcePolicyRetention(policy, now));
    }

    await this.auditService.log('system', 'privacy.retention.enforced', undefined, {
      runAt,
      results,
    });

    return { runAt, results };
  }

  async eraseSubject(
    subject: ErasureSubject,
    requestedBy = 'system',
  ): Promise<PrivacyWorkflowResult> {
    if (!subject.publicKey && !subject.username && !subject.userId) {
      throw new BadRequestException(
        'At least one erasure subject identifier is required',
      );
    }

    const runAt = new Date().toISOString();
    const results: StoreRetentionResult[] = [];

    for (const policy of DATA_RETENTION_POLICIES) {
      const matches = this.getSubjectMatches(policy, subject);
      if (matches.length === 0) {
        results.push({
          storeKey: policy.storeKey,
          tableName: policy.tableName,
          action: policy.action,
          affectedRows: 0,
        });
        continue;
      }

      let affectedRows = 0;
      const errors: string[] = [];

      for (const match of matches) {
        const result = await this.applySubjectErasure(policy, match, subject);
        affectedRows += result.affectedRows;
        if (result.error) errors.push(result.error);
      }

      results.push({
        storeKey: policy.storeKey,
        tableName: policy.tableName,
        action: policy.action,
        affectedRows,
        ...(errors.length > 0 && { error: errors.join('; ') }),
      });
    }

    await this.auditService.log(requestedBy, 'privacy.erasure.completed', undefined, {
      runAt,
      subject: this.maskSubject(subject),
      results,
    });

    return { runAt, results };
  }

  private async enforcePolicyRetention(
    policy: RetentionPolicy,
    now: Date,
  ): Promise<StoreRetentionResult> {
    try {
      const client = this.supabaseService.getClient();
      const cutoff = this.getRetentionCutoff(policy, now);
      const table = client.from(policy.tableName) as unknown as QueryBuilder;
      const query = policy.action === 'delete'
        ? this.requireMethod(table, 'delete')()
        : this.requireMethod(table, 'update')(
            this.buildAnonymizedValues(policy, { retentionRunAt: now.toISOString() }),
          );

      this.requireMethod(query, 'lt')(policy.retentionColumn, cutoff);
      const { data, error } = await this.requireMethod(query, 'select')('id');

      if (error) {
        throw new Error(error.message ?? 'Supabase retention query failed');
      }

      const affectedRows = data?.length ?? 0;
      if (affectedRows > 0) {
        this.logger.log(
          `${policy.action}d ${affectedRows} rows from ${policy.tableName} during retention enforcement`,
        );
      }

      return {
        storeKey: policy.storeKey,
        tableName: policy.tableName,
        action: policy.action,
        affectedRows,
      };
    } catch (error) {
      const message = (error as Error).message;
      this.logger.warn(
        `Retention enforcement failed for ${policy.tableName}: ${message}`,
      );
      return {
        storeKey: policy.storeKey,
        tableName: policy.tableName,
        action: policy.action,
        affectedRows: 0,
        error: message,
      };
    }
  }

  private async applySubjectErasure(
    policy: RetentionPolicy,
    match: { column: string; value: string },
    subject: ErasureSubject,
  ): Promise<StoreRetentionResult> {
    try {
      const client = this.supabaseService.getClient();
      const table = client.from(policy.tableName) as unknown as QueryBuilder;
      const query = policy.action === 'delete'
        ? this.requireMethod(table, 'delete')()
        : this.requireMethod(table, 'update')(
            this.buildAnonymizedValues(policy, {
              subject,
              matchedColumn: match.column,
            }),
          );

      this.requireMethod(query, 'eq')(match.column, match.value);
      const { data, error } = await this.requireMethod(query, 'select')('id');

      if (error) {
        throw new Error(error.message ?? 'Supabase erasure query failed');
      }

      return {
        storeKey: policy.storeKey,
        tableName: policy.tableName,
        action: policy.action,
        affectedRows: data?.length ?? 0,
      };
    } catch (error) {
      const message = (error as Error).message;
      this.logger.warn(
        `Erasure failed for ${policy.tableName}.${match.column}: ${message}`,
      );
      return {
        storeKey: policy.storeKey,
        tableName: policy.tableName,
        action: policy.action,
        affectedRows: 0,
        error: message,
      };
    }
  }

  private getRetentionCutoff(policy: RetentionPolicy, now: Date): string {
    if (policy.cutoffMode === 'absolute') {
      return now.toISOString();
    }

    return new Date(
      now.getTime() - policy.retentionDays * 24 * 60 * 60 * 1000,
    ).toISOString();
  }

  private getSubjectMatches(
    policy: RetentionPolicy,
    subject: ErasureSubject,
  ): Array<{ column: string; value: string }> {
    const seen = new Set<string>();
    const matches: Array<{ column: string; value: string }> = [];

    for (const identifier of policy.subjectIdentifiers) {
      const value = this.getSubjectValue(identifier, subject);
      if (!value) continue;

      const dedupeKey = `${identifier.column}:${value}`;
      if (seen.has(dedupeKey)) continue;
      seen.add(dedupeKey);
      matches.push({ column: identifier.column, value });
    }

    return matches;
  }

  private getSubjectValue(
    identifier: SubjectIdentifier,
    subject: ErasureSubject,
  ): string | undefined {
    const value = subject[identifier.key as PrivacySubjectKey];
    return value?.trim() || undefined;
  }

  private buildAnonymizedValues(
    policy: RetentionPolicy,
    context: {
      subject?: ErasureSubject;
      matchedColumn?: string;
      retentionRunAt?: string;
    },
  ): Record<string, unknown> {
    const anonymized = this.anonymizedSubjectValue(policy, context);
    const values: Record<string, unknown> = { ...(policy.setColumns ?? {}) };

    for (const column of policy.anonymizeColumns ?? []) {
      values[column] = anonymized;
    }
    for (const column of policy.nullColumns ?? []) {
      values[column] = null;
    }
    if (policy.tableName === 'support_bundle_references') {
      values.redacted_at = context.retentionRunAt ?? new Date().toISOString();
    }

    return values;
  }

  private anonymizedSubjectValue(
    policy: RetentionPolicy,
    context: {
      subject?: ErasureSubject;
      matchedColumn?: string;
      retentionRunAt?: string;
    },
  ): string {
    const source = JSON.stringify({
      storeKey: policy.storeKey,
      subject: context.subject ?? null,
      matchedColumn: context.matchedColumn ?? null,
      retentionRunAt: context.retentionRunAt ?? null,
    });

    const digest = createHash('sha256').update(source).digest('hex').slice(0, 24);
    return `erased:${digest}`;
  }

  private maskSubject(subject: ErasureSubject): Record<string, string> {
    return Object.fromEntries(
      Object.entries(subject)
        .filter(([, value]) => value)
        .map(([key, value]) => [
          key,
          this.anonymizedSubjectValue(
            {
              storeKey: `audit-${key}`,
              tableName: 'audit',
              description: 'audit subject mask',
              retentionDays: 0,
              retentionColumn: 'created_at',
              cutoffMode: 'age',
              action: 'anonymize',
              subjectIdentifiers: [],
            },
            { subject: { [key]: value } as ErasureSubject },
          ),
        ]),
    );
  }

  private requireMethod<TName extends keyof QueryBuilder>(
    query: QueryBuilder,
    method: TName,
  ): NonNullable<QueryBuilder[TName]> {
    const fn = query[method];
    if (!fn) {
      throw new Error(`Supabase query missing ${String(method)} method`);
    }
    return fn.bind(query) as NonNullable<QueryBuilder[TName]>;
  }
}
