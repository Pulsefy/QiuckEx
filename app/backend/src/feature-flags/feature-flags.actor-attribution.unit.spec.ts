/**
 * Unit tests for feature-flag audit actor attribution (issue #26).
 *
 * Tests cover:
 * - Actor resolved from req.apiKey.id (primary)
 * - Fallback to X-Admin-Actor header
 * - Anonymous changes blocked (no apiKey, no header)
 * - FlagAuditEntry shape recorded in audit log
 */

import { Test, TestingModule } from '@nestjs/testing';
import { ForbiddenException } from '@nestjs/common';
import { FeatureFlagsController } from './feature-flags.controller';
import { FeatureFlagsService } from './feature-flags.service';
import { AuditService } from '../audit/audit.service';
import { FeatureFlagRecord } from './feature-flags.dto';
import { Request } from 'express';

const mockFlag: FeatureFlagRecord = {
  key: 'test.flag',
  name: 'Test Flag',
  description: '',
  enabled: true,
  killSwitch: false,
  rolloutPercentage: 100,
  allowedUsers: [],
  environments: [],
  metadata: {},
  updatedAt: new Date(0).toISOString(),
  updatedBy: 'bootstrap',
};

function buildMockRequest(overrides: Record<string, unknown> = {}): Request {
  return {
    ip: '127.0.0.1',
    headers: { 'user-agent': 'jest-test' },
    ...overrides,
  } as unknown as Request;
}

describe('FeatureFlagsController — actor attribution (issue #26)', () => {
  let controller: FeatureFlagsController;
  let featureFlagsService: jest.Mocked<Pick<FeatureFlagsService, 'getFlagOrThrow' | 'updateFlag'>>;
  let auditService: jest.Mocked<Pick<AuditService, 'log'>>;

  beforeEach(async () => {
    featureFlagsService = {
      getFlagOrThrow: jest.fn().mockResolvedValue(mockFlag),
      updateFlag: jest.fn().mockResolvedValue({ ...mockFlag, enabled: false }),
    };
    auditService = {
      log: jest.fn().mockResolvedValue(undefined),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [FeatureFlagsController],
      providers: [
        { provide: FeatureFlagsService, useValue: featureFlagsService },
        { provide: AuditService, useValue: auditService },
      ],
    }).compile();

    controller = module.get(FeatureFlagsController);
  });

  afterEach(() => jest.clearAllMocks());

  describe('updateFlag', () => {
    it('uses apiKey.id as actor when present', async () => {
      const req = buildMockRequest({ apiKey: { id: 'key-abc-123' } });
      await controller.updateFlag('test.flag', { enabled: false }, req, undefined);
      expect(featureFlagsService.updateFlag).toHaveBeenCalledWith(
        'test.flag',
        { enabled: false },
        'apiKey:key-abc-123',
      );
    });

    it('falls back to X-Admin-Actor header when no apiKey', async () => {
      const req = buildMockRequest();
      await controller.updateFlag('test.flag', { enabled: false }, req, 'admin-dashboard');
      expect(featureFlagsService.updateFlag).toHaveBeenCalledWith(
        'test.flag',
        { enabled: false },
        'admin-dashboard',
      );
    });

    it('blocks anonymous requests (no apiKey, no header)', async () => {
      const req = buildMockRequest();
      await expect(
        controller.updateFlag('test.flag', { enabled: false }, req, undefined),
      ).rejects.toBeInstanceOf(ForbiddenException);
    });

    it('blocks anonymous requests with whitespace-only X-Admin-Actor', async () => {
      const req = buildMockRequest();
      await expect(
        controller.updateFlag('test.flag', { enabled: false }, req, '   '),
      ).rejects.toBeInstanceOf(ForbiddenException);
    });

    it('records a FlagAuditEntry with ip and userAgent in audit log', async () => {
      const req = buildMockRequest({ apiKey: { id: 'key-xyz' } });
      await controller.updateFlag('test.flag', { enabled: false }, req, undefined);

      expect(auditService.log).toHaveBeenCalledWith(
        'apiKey:key-xyz',
        'feature_flag.updated',
        'test.flag',
        expect.objectContaining({
          flagAuditEntry: expect.objectContaining({
            flagKey: 'test.flag',
            actor: 'apiKey:key-xyz',
            ip: '127.0.0.1',
            userAgent: 'jest-test',
            previousValue: expect.objectContaining({ key: 'test.flag' }),
            newValue: expect.objectContaining({ key: 'test.flag', enabled: false }),
          }),
        }),
        undefined, // correlationId
      );
    });

    it('prefers apiKey.id over X-Admin-Actor header', async () => {
      const req = buildMockRequest({ apiKey: { id: 'key-primary' } });
      await controller.updateFlag('test.flag', { enabled: false }, req, 'some-header-actor');
      expect(featureFlagsService.updateFlag).toHaveBeenCalledWith(
        'test.flag',
        { enabled: false },
        'apiKey:key-primary',
      );
    });
  });
});
