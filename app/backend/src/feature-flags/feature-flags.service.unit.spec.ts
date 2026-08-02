import { Test, TestingModule } from '@nestjs/testing';

import { AppConfigService } from '../config';
import { AuditService } from '../audit/audit.service';
import { PreviewScopeService } from '../preview-scope/preview-scope.service';
import { SupabaseService } from '../supabase/supabase.service';
import { FeatureFlagsService } from './feature-flags.service';

describe('FeatureFlagsService', () => {
  let service: FeatureFlagsService;

  const mockAuditService = {
    log: jest.fn(),
  };

  const mockConfigService = {
    nodeEnv: 'test',
    featureFlagsCacheTtlMs: 10_000,
    featureFlagsBootstrapJson: '',
  };

  const mockSupabaseService = {
    getClient: jest.fn(),
  };

  const mockPreviewScopeService = {
    isValidScope: jest.fn().mockResolvedValue(true),
    getScope: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        FeatureFlagsService,
        { provide: SupabaseService, useValue: mockSupabaseService },
        { provide: AuditService, useValue: mockAuditService },
        { provide: AppConfigService, useValue: mockConfigService },
        { provide: PreviewScopeService, useValue: mockPreviewScopeService },
      ],
    }).compile();

    service = module.get<FeatureFlagsService>(FeatureFlagsService);
    jest.clearAllMocks();
  });

  it('falls back to bootstrap flags when store is unavailable', async () => {
    mockSupabaseService.getClient.mockReturnValue({
      from: jest.fn().mockReturnValue({
        select: jest.fn().mockReturnThis(),
        order: jest.fn().mockRejectedValue(new Error('offline')),
      }),
    });

    const result = await service.listFlags();

    expect(result.storeAvailable).toBe(false);
    expect(result.flags.some((flag) => flag.key === 'bulk_link_generation')).toBe(true);
  });

  it('evaluates allowlist and rollout rules deterministically', async () => {
    mockSupabaseService.getClient.mockReturnValue({
      from: jest.fn().mockReturnValue({
        select: jest.fn().mockReturnThis(),
        order: jest.fn().mockResolvedValue({
          data: [
            {
              key: 'bulk_link_generation',
              enabled: true,
              kill_switch: false,
              rollout_percentage: 10,
              allowed_users: ['vip-user'],
              environments: ['test'],
              metadata: {},
              updated_at: new Date().toISOString(),
              updated_by: 'seed',
            },
          ],
          error: null,
        }),
      }),
    });

    const allowlisted = await service.evaluateFlag('bulk_link_generation', {
      userId: 'vip-user',
      environment: 'test',
    });
    const missingUser = await service.evaluateFlag('bulk_link_generation', {
      environment: 'test',
    });

    expect(allowlisted.enabled).toBe(true);
    expect(allowlisted.reason).toBe('allowlist-match');
    expect(missingUser.enabled).toBe(false);
    expect(missingUser.reason).toBe('missing-user-context');
  });

  it('fresh evaluation bypasses stale cache state', async () => {
    mockSupabaseService.getClient.mockReturnValueOnce({
      from: jest.fn().mockReturnValue({
        select: jest.fn().mockReturnThis(),
        order: jest.fn().mockResolvedValue({
          data: [
            {
              key: 'testnet.contract_writes',
              enabled: true,
              kill_switch: false,
              rollout_percentage: 100,
              allowed_users: [],
              environments: ['test'],
              metadata: {},
              updated_at: new Date().toISOString(),
              updated_by: 'ops',
            },
          ],
          error: null,
        }),
      }),
    });

    await service.listFlags();

    mockSupabaseService.getClient.mockReturnValue({
      from: jest.fn().mockReturnValue({
        select: jest.fn().mockReturnThis(),
        order: jest.fn().mockResolvedValue({
          data: [
            {
              key: 'testnet.contract_writes',
              enabled: false,
              kill_switch: true,
              rollout_percentage: 0,
              allowed_users: [],
              environments: ['test'],
              metadata: {},
              updated_at: new Date().toISOString(),
              updated_by: 'ops',
            },
          ],
          error: null,
        }),
      }),
    });

    const fresh = await service.evaluateFlagFresh('testnet.contract_writes', {
      environment: 'test',
    });

    expect(fresh.enabled).toBe(false);
    expect(fresh.reason).toBe('kill-switch');
  });

  it('updates a flag and writes an audit entry', async () => {
    const selectBuilder = {
      select: jest.fn().mockReturnThis(),
      order: jest.fn().mockResolvedValue({
        data: [
          {
            key: 'bulk_link_generation',
            name: 'Bulk Link Generation',
            description: 'Controls new bulk payment-link creation requests.',
            enabled: true,
            kill_switch: false,
            rollout_percentage: 100,
            allowed_users: [],
            environments: ['development', 'test', 'production'],
            metadata: {},
            updated_at: new Date().toISOString(),
            updated_by: 'seed',
          },
        ],
        error: null,
      }),
    };

    const upsertBuilder = {
      upsert: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      single: jest.fn().mockResolvedValue({
        data: {
          key: 'bulk_link_generation',
          name: 'Bulk Link Generation',
          description: 'Controls new bulk payment-link creation requests.',
          enabled: false,
          kill_switch: true,
          rollout_percentage: 0,
          allowed_users: [],
          environments: ['test'],
          metadata: {},
          updated_at: new Date().toISOString(),
          updated_by: 'admin',
        },
        error: null,
      }),
    };

    mockSupabaseService.getClient.mockReturnValue({
      from: jest.fn((table: string) => {
        if (table === 'feature_flags') {
          return {
            ...selectBuilder,
            upsert: upsertBuilder.upsert,
            single: upsertBuilder.single,
          };
        }
        return selectBuilder;
      }),
    });

    const result = await service.updateFlag(
      'bulk_link_generation',
      { enabled: false, killSwitch: true, rolloutPercentage: 0, environments: ['test'] },
      'admin',
    );

    expect(result.killSwitch).toBe(true);
    expect(mockAuditService.log).toHaveBeenCalledWith(
      'admin',
      'feature_flag.updated',
      'bulk_link_generation',
      expect.any(Object),
    );
  });

  describe('getSnapshot', () => {
    it('returns all bootstrap flags when store is unavailable', async () => {
      mockSupabaseService.getClient.mockReturnValue({
        from: jest.fn().mockReturnValue({
          select: jest.fn().mockReturnThis(),
          order: jest.fn().mockRejectedValue(new Error('offline')),
        }),
      });

      const result = await service.getSnapshot();

      expect(result.metadata.source).toBe('bootstrap');
      expect(result.metadata.storeAvailable).toBe(false);
      expect(result.metadata.flagCount).toBeGreaterThan(0);
      expect(result.flags.every((f) => typeof f.key === 'string')).toBe(true);
      expect(result.flags.every((f) => typeof f.enabled === 'boolean')).toBe(true);
    });

    it('filters flags by environment', async () => {
      mockSupabaseService.getClient.mockReturnValue({
        from: jest.fn().mockReturnValue({
          select: jest.fn().mockReturnThis(),
          order: jest.fn().mockResolvedValue({
            data: [
              {
                key: 'mainnet.refunds',
                name: 'Mainnet Refunds',
                description: 'Allows refund initiation on mainnet.',
                enabled: false,
                kill_switch: false,
                rollout_percentage: 0,
                allowed_users: [],
                environments: ['production'],
                metadata: {},
                updated_at: new Date(0).toISOString(),
                updated_by: 'bootstrap',
              },
              {
                key: 'bulk_link_generation',
                name: 'Bulk Link Generation',
                description: 'Controls bulk payment-link creation.',
                enabled: true,
                kill_switch: false,
                rollout_percentage: 100,
                allowed_users: [],
                environments: ['development', 'test', 'production'],
                metadata: {},
                updated_at: new Date().toISOString(),
                updated_by: 'seed',
              },
            ],
            error: null,
          }),
        }),
      });

      const result = await service.getSnapshot('production');

      expect(result.metadata.environment).toBe('production');
      expect(result.flags.map((f) => f.key)).toContain('bulk_link_generation');
      expect(result.flags.map((f) => f.key)).toContain('mainnet.refunds');
    });

    it('excludes flags with sensitive/internal metadata', async () => {
      mockSupabaseService.getClient.mockReturnValue({
        from: jest.fn().mockReturnValue({
          select: jest.fn().mockReturnThis(),
          order: jest.fn().mockResolvedValue({
            data: [
              {
                key: 'bulk_link_generation',
                name: 'Bulk Link Generation',
                description: 'Controls bulk payment-link creation.',
                enabled: true,
                kill_switch: false,
                rollout_percentage: 100,
                allowed_users: [],
                environments: ['development', 'test', 'production'],
                metadata: {},
                updated_at: new Date().toISOString(),
                updated_by: 'seed',
              },
              {
                key: 'internal.debug_logging',
                name: 'Debug Logging',
                description: 'Internal debug flag.',
                enabled: true,
                kill_switch: false,
                rollout_percentage: 100,
                allowed_users: [],
                environments: ['development'],
                metadata: { internal: true },
                updated_at: new Date().toISOString(),
                updated_by: 'ops',
              },
              {
                key: 'sensitive.pii_feature',
                name: 'PII Feature',
                description: 'Feature exposing PII.',
                enabled: true,
                kill_switch: false,
                rollout_percentage: 100,
                allowed_users: [],
                environments: ['development'],
                metadata: { sensitive: true },
                updated_at: new Date().toISOString(),
                updated_by: 'ops',
              },
            ],
            error: null,
          }),
        }),
      });

      const result = await service.getSnapshot();

      expect(result.metadata.sensitiveFlagCount).toBe(2);
      expect(result.flags.map((f) => f.key)).not.toContain('internal.debug_logging');
      expect(result.flags.map((f) => f.key)).not.toContain('sensitive.pii_feature');
      expect(result.flags.map((f) => f.key)).toContain('bulk_link_generation');
    });

    it('includes preview scope metadata when header is present', async () => {
      mockSupabaseService.getClient.mockReturnValue({
        from: jest.fn().mockReturnValue({
          select: jest.fn().mockReturnThis(),
          order: jest.fn().mockResolvedValue({
            data: [
              {
                key: 'bulk_link_generation',
                name: 'Bulk Link Generation',
                description: 'Controls bulk payment-link creation.',
                enabled: true,
                kill_switch: false,
                rollout_percentage: 100,
                allowed_users: [],
                environments: ['development', 'test', 'production'],
                metadata: {},
                updated_at: new Date().toISOString(),
                updated_by: 'seed',
              },
            ],
            error: null,
          }),
        }),
      });
      mockPreviewScopeService.isValidScope.mockResolvedValue(true);

      const result = await service.getSnapshot(undefined, 'pr-42');

      expect(result.metadata.previewScope).toBe('pr-42');
      expect(result.metadata.previewScopeValid).toBe(true);
      expect(result.flags[0].previewOverrideActive).toBe(true);
    });

    it('reports invalid preview scope', async () => {
      mockSupabaseService.getClient.mockReturnValue({
        from: jest.fn().mockReturnValue({
          select: jest.fn().mockReturnThis(),
          order: jest.fn().mockResolvedValue({
            data: [
              {
                key: 'bulk_link_generation',
                name: 'Bulk Link Generation',
                description: 'Controls bulk payment-link creation.',
                enabled: true,
                kill_switch: false,
                rollout_percentage: 100,
                allowed_users: [],
                environments: ['development', 'test', 'production'],
                metadata: {},
                updated_at: new Date().toISOString(),
                updated_by: 'seed',
              },
            ],
            error: null,
          }),
        }),
      });
      mockPreviewScopeService.isValidScope.mockResolvedValue(false);

      const result = await service.getSnapshot(undefined, 'expired-scope');

      expect(result.metadata.previewScope).toBe('expired-scope');
      expect(result.metadata.previewScopeValid).toBe(false);
      expect(result.flags[0].previewOverrideActive).toBe(false);
    });

    it('handles preview scope service failure gracefully', async () => {
      mockSupabaseService.getClient.mockReturnValue({
        from: jest.fn().mockReturnValue({
          select: jest.fn().mockReturnThis(),
          order: jest.fn().mockResolvedValue({
            data: [
              {
                key: 'bulk_link_generation',
                name: 'Bulk Link Generation',
                description: 'Controls bulk payment-link creation.',
                enabled: true,
                kill_switch: false,
                rollout_percentage: 100,
                allowed_users: [],
                environments: ['development', 'test', 'production'],
                metadata: {},
                updated_at: new Date().toISOString(),
                updated_by: 'seed',
              },
            ],
            error: null,
          }),
        }),
      });
      mockPreviewScopeService.isValidScope.mockRejectedValue(new Error('db down'));

      const result = await service.getSnapshot(undefined, 'pr-99');

      expect(result.metadata.previewScope).toBe('pr-99');
      expect(result.metadata.previewScopeValid).toBeUndefined();
      expect(result.flags.length).toBeGreaterThan(0);
      expect(result.flags.some((f) => f.key === 'bulk_link_generation')).toBe(true);
    });

    it('reflects overridden flag state from store', async () => {
      mockSupabaseService.getClient.mockReturnValue({
        from: jest.fn().mockReturnValue({
          select: jest.fn().mockReturnThis(),
          order: jest.fn().mockResolvedValue({
            data: [
              {
                key: 'bulk_link_generation',
                name: 'Bulk Link Generation',
                description: 'Controls bulk payment-link creation.',
                enabled: false,
                kill_switch: true,
                rollout_percentage: 0,
                allowed_users: [],
                environments: ['test'],
                metadata: {},
                updated_at: new Date().toISOString(),
                updated_by: 'admin',
              },
            ],
            error: null,
          }),
        }),
      });

      const result = await service.getSnapshot('test');

      const overridden = result.flags.find((f) => f.key === 'bulk_link_generation');
      expect(overridden).toBeDefined();
      expect(overridden!.enabled).toBe(false);
      expect(overridden!.killSwitch).toBe(true);
      expect(overridden!.rolloutPercentage).toBe(0);
      expect(overridden!.updatedBy).toBe('admin');
    });
  });
});
