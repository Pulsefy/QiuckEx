import { NotFoundException } from '@nestjs/common';

import { SupabaseService } from '../../supabase/supabase.service';
import { AuditService } from '../../audit/audit.service';
import { SupportBundleReferenceService } from '../support-bundle-reference.service';
import { redactValue } from '../../common/utils/redaction.util';

describe('SupportBundleReferenceService', () => {
  let service: SupportBundleReferenceService;
  let mockAuditService: jest.Mocked<Partial<AuditService>>;

  beforeEach(() => {
    // Force fallback (in-memory) storage: Supabase client throws.
    const mockSupabaseService: Partial<SupabaseService> = {
      getClient: jest.fn(() => {
        throw new Error('supabase unavailable');
      }) as never,
    };

    mockAuditService = {
      log: jest.fn().mockResolvedValue(undefined),
    };

    service = new SupportBundleReferenceService(
      mockSupabaseService as SupabaseService,
      mockAuditService as unknown as AuditService,
    );
  });

  describe('create', () => {
    it('creates a reference, masks the bundle id, and audits the action', async () => {
      const result = await service.create(
        { bundleId: 'bundle_9f8c1e2a4b3d', targetType: 'receipt', targetId: 'rcpt_abc123_0' },
        'api-key-1',
      );

      expect(result.id).toBeDefined();
      expect(result.targetType).toBe('receipt');
      expect(result.targetId).toBe('rcpt_abc123_0');
      expect(result.redacted).toBe(false);
      expect(result.bundleIdMasked).toBe(redactValue('bundle_9f8c1e2a4b3d'));
      expect(result.bundleIdMasked).not.toBe('bundle_9f8c1e2a4b3d');

      expect(mockAuditService.log).toHaveBeenCalledWith(
        'api-key-1',
        'support_bundle_reference.created',
        result.id,
        expect.objectContaining({ targetType: 'receipt', targetId: 'rcpt_abc123_0' }),
      );
    });

    it('defaults expiry to 30 days and respects a custom ttlDays', async () => {
      const now = Date.now();

      const withDefault = await service.create(
        { bundleId: 'bundle-default', targetType: 'issue_report', targetId: 'issue-1' },
        'api-key-1',
      );
      const defaultDays =
        (new Date(withDefault.expiresAt).getTime() - now) / (24 * 60 * 60 * 1000);
      expect(defaultDays).toBeGreaterThan(29.9);
      expect(defaultDays).toBeLessThan(30.1);

      const withCustom = await service.create(
        { bundleId: 'bundle-custom', targetType: 'issue_report', targetId: 'issue-2', ttlDays: 5 },
        'api-key-1',
      );
      const customDays =
        (new Date(withCustom.expiresAt).getTime() - now) / (24 * 60 * 60 * 1000);
      expect(customDays).toBeGreaterThan(4.9);
      expect(customDays).toBeLessThan(5.1);
    });
  });

  describe('findById', () => {
    it('returns a reference that exists and has not expired', async () => {
      const created = await service.create(
        { bundleId: 'bundle-1', targetType: 'receipt', targetId: 'rcpt-1' },
        'api-key-1',
      );

      const found = await service.findById(created.id);
      expect(found.id).toBe(created.id);
    });

    it('throws NotFoundException for an unknown id', async () => {
      await expect(service.findById('does-not-exist')).rejects.toBeInstanceOf(NotFoundException);
    });

    it('throws NotFoundException once the reference has expired', async () => {
      const created = await service.create(
        { bundleId: 'bundle-1', targetType: 'receipt', targetId: 'rcpt-1' },
        'api-key-1',
      );

      const store = (
        service as unknown as {
          fallbackStore: Map<string, { expiresAt: string }>;
        }
      ).fallbackStore;
      store.get(created.id)!.expiresAt = new Date(Date.now() - 1000).toISOString();

      await expect(service.findById(created.id)).rejects.toBeInstanceOf(NotFoundException);
    });
  });

  describe('findByTarget', () => {
    it('returns only non-expired, non-redacted references for the target', async () => {
      const active = await service.create(
        { bundleId: 'bundle-active', targetType: 'receipt', targetId: 'rcpt-shared' },
        'api-key-1',
      );
      const expired = await service.create(
        { bundleId: 'bundle-expired', targetType: 'receipt', targetId: 'rcpt-shared' },
        'api-key-1',
      );
      await service.create(
        { bundleId: 'bundle-other-target', targetType: 'receipt', targetId: 'rcpt-other' },
        'api-key-1',
      );

      const store = (
        service as unknown as {
          fallbackStore: Map<string, { expiresAt: string }>;
        }
      ).fallbackStore;
      store.get(expired.id)!.expiresAt = new Date(Date.now() - 1000).toISOString();

      const results = await service.findByTarget('receipt', 'rcpt-shared');
      expect(results).toHaveLength(1);
      expect(results[0].id).toBe(active.id);
    });

    it('never exposes the raw bundle id in lookups', async () => {
      await service.create(
        { bundleId: 'super-secret-bundle-id', targetType: 'issue_report', targetId: 'issue-9' },
        'api-key-1',
      );

      const results = await service.findByTarget('issue_report', 'issue-9');
      expect(results).toHaveLength(1);
      expect(results[0].bundleIdMasked).not.toBe('super-secret-bundle-id');
      expect(JSON.stringify(results)).not.toContain('super-secret-bundle-id');
    });
  });

  describe('redact', () => {
    it('marks a reference redacted and excludes it from future lookups', async () => {
      const created = await service.create(
        { bundleId: 'bundle-1', targetType: 'receipt', targetId: 'rcpt-redact' },
        'api-key-1',
      );

      const redacted = await service.redact(created.id, 'admin-1');
      expect(redacted.redacted).toBe(true);

      await expect(service.findById(created.id)).rejects.toBeInstanceOf(NotFoundException);
      const results = await service.findByTarget('receipt', 'rcpt-redact');
      expect(results).toHaveLength(0);

      expect(mockAuditService.log).toHaveBeenCalledWith(
        'admin-1',
        'support_bundle_reference.redacted',
        created.id,
        expect.objectContaining({ targetType: 'receipt', targetId: 'rcpt-redact' }),
      );
    });

    it('throws NotFoundException when redacting an unknown id', async () => {
      await expect(service.redact('does-not-exist', 'admin-1')).rejects.toBeInstanceOf(
        NotFoundException,
      );
    });
  });

  describe('cleanupExpired', () => {
    it('redacts references past their expiry in the fallback store', async () => {
      const created = await service.create(
        { bundleId: 'bundle-1', targetType: 'receipt', targetId: 'rcpt-1' },
        'api-key-1',
      );

      const store = (
        service as unknown as {
          fallbackStore: Map<string, { expiresAt: string }>;
        }
      ).fallbackStore;
      store.get(created.id)!.expiresAt = new Date(Date.now() - 1000).toISOString();

      const count = await service.cleanupExpired();
      expect(count).toBe(1);
      await expect(service.findById(created.id)).rejects.toBeInstanceOf(NotFoundException);
    });

    it('does not touch references that have not expired', async () => {
      await service.create(
        { bundleId: 'bundle-1', targetType: 'receipt', targetId: 'rcpt-1' },
        'api-key-1',
      );

      const count = await service.cleanupExpired();
      expect(count).toBe(0);
    });
  });
});
