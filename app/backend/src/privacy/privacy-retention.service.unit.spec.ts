import { BadRequestException } from '@nestjs/common';

import { AuditService } from '../audit/audit.service';
import { SupabaseService } from '../supabase/supabase.service';
import { DATA_RETENTION_POLICIES } from './data-retention.policy';
import { PrivacyRetentionService } from './privacy-retention.service';

class FakeQuery {
  operation: 'delete' | 'update' | null = null;
  updatePayload: Record<string, unknown> | null = null;
  filters: Array<{ method: 'eq' | 'lt'; column: string; value: unknown }> = [];

  constructor(
    readonly tableName: string,
    private readonly rows: unknown[] = [{ id: 'row-1' }],
  ) {}

  delete() {
    this.operation = 'delete';
    return this;
  }

  update(values: Record<string, unknown>) {
    this.operation = 'update';
    this.updatePayload = values;
    return this;
  }

  eq(column: string, value: unknown) {
    this.filters.push({ method: 'eq', column, value });
    return this;
  }

  lt(column: string, value: unknown) {
    this.filters.push({ method: 'lt', column, value });
    return this;
  }

  async select() {
    return { data: this.rows, error: null };
  }
}

describe('PrivacyRetentionService', () => {
  let service: PrivacyRetentionService;
  let queries: FakeQuery[];
  let auditService: jest.Mocked<Partial<AuditService>>;

  beforeEach(() => {
    queries = [];
    const supabaseService: Partial<SupabaseService> = {
      getClient: jest.fn(() => ({
        from: (tableName: string) => {
          const query = new FakeQuery(tableName);
          queries.push(query);
          return query;
        },
      })) as never,
    };

    auditService = {
      log: jest.fn().mockResolvedValue(undefined),
    };

    service = new PrivacyRetentionService(
      supabaseService as SupabaseService,
      auditService as unknown as AuditService,
    );
  });

  it('declares retention for each personal-data store centrally', () => {
    const tableNames = DATA_RETENTION_POLICIES.map((policy) => policy.tableName);

    expect(new Set(tableNames).size).toBe(tableNames.length);
    expect(tableNames).toEqual(
      expect.arrayContaining([
        'usernames',
        'crash_reports',
        'crash_reporting_settings',
        'notification_preferences',
        'notification_log',
        'abuse_signals',
        'support_bundle_references',
        'payment_links',
        'recurring_payment_links',
        'unmatched_transactions',
        'admin_audit_logs',
      ]),
    );
    expect(
      DATA_RETENTION_POLICIES.every(
        (policy) => policy.retentionDays > 0 && policy.retentionColumn,
      ),
    ).toBe(true);
  });

  it('documents stores that are anonymized for financial or audit integrity', () => {
    const anonymizedStores = DATA_RETENTION_POLICIES.filter(
      (policy) => policy.action === 'anonymize',
    );

    expect(anonymizedStores.length).toBeGreaterThan(0);
    expect(
      anonymizedStores.every((policy) => policy.financialIntegrityNote),
    ).toBe(true);
  });

  it('enforces retention across every declared store and records the run', async () => {
    const result = await service.enforceRetention(new Date('2026-08-25T00:00:00.000Z'));

    expect(result.results).toHaveLength(DATA_RETENTION_POLICIES.length);
    expect(queries.map((query) => query.tableName)).toEqual(
      DATA_RETENTION_POLICIES.map((policy) => policy.tableName),
    );
    expect(queries.every((query) => query.filters[0]?.method === 'lt')).toBe(true);
    expect(auditService.log).toHaveBeenCalledWith(
      'system',
      'privacy.retention.enforced',
      undefined,
      expect.objectContaining({ results: expect.any(Array) }),
    );
  });

  it('services erasure across every declared store', async () => {
    const result = await service.eraseSubject(
      {
        publicKey: 'GABC123',
        username: 'alice',
        userId: 'user-123',
      },
      'admin-key',
    );

    expect(result.results).toHaveLength(DATA_RETENTION_POLICIES.length);
    expect(new Set(result.results.map((item) => item.tableName))).toEqual(
      new Set(DATA_RETENTION_POLICIES.map((policy) => policy.tableName)),
    );

    const paymentLinkQuery = queries.find(
      (query) => query.tableName === 'payment_links' && query.operation === 'update',
    );
    expect(paymentLinkQuery?.updatePayload).toEqual(
      expect.objectContaining({
        owner_public_key: expect.stringMatching(/^erased:/),
        destination_public_key: expect.stringMatching(/^erased:/),
        memo: null,
        reference_id: null,
      }),
    );

    const usernameQuery = queries.find((query) => query.tableName === 'usernames');
    expect(usernameQuery?.operation).toBe('delete');

    expect(auditService.log).toHaveBeenCalledWith(
      'admin-key',
      'privacy.erasure.completed',
      undefined,
      expect.objectContaining({
        subject: expect.objectContaining({
          publicKey: expect.stringMatching(/^erased:/),
          username: expect.stringMatching(/^erased:/),
          userId: expect.stringMatching(/^erased:/),
        }),
      }),
    );
  });

  it('requires at least one subject identifier for erasure', async () => {
    await expect(service.eraseSubject({})).rejects.toBeInstanceOf(
      BadRequestException,
    );
  });
});

