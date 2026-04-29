import { Test, TestingModule } from '@nestjs/testing';

import { AppConfigService } from '../config';
import { AuditService } from '../audit/audit.service';
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

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        FeatureFlagsService,
        { provide: SupabaseService, useValue: mockSupabaseService },
        { provide: AuditService, useValue: mockAuditService },
        { provide: AppConfigService, useValue: mockConfigService },
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
});
