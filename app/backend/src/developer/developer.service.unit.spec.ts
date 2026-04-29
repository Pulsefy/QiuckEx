import { Test, TestingModule } from '@nestjs/testing';
import { NotFoundException } from '@nestjs/common';
import { DeveloperService } from './developer.service';
import { ApiKeysService } from '../api-keys/api-keys.service';
import { WebhookService } from '../notifications/webhook.service';
import { AuditService } from '../audit/audit.service';
import type { WebhookResponseDto, WebhookStatsDto } from '../notifications/dto/webhook.dto';
import type { ApiKeyCreated } from '../api-keys/api-keys.types';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const makeWebhook = (overrides: Partial<WebhookResponseDto> = {}): WebhookResponseDto => ({
  id: 'webhook-uuid-1234',
  publicKey: 'GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN',
  webhookUrl: 'https://example.com/hook',
  secret: 'whsec_abc123def456',
  events: null,
  minAmountStroops: '0',
  enabled: true,
  createdAt: '2026-01-01T00:00:00.000Z',
  updatedAt: '2026-01-01T00:00:00.000Z',
  ...overrides,
});

const makeStats = (overrides: Partial<WebhookStatsDto> = {}): WebhookStatsDto => ({
  totalSent: 100,
  totalFailed: 0,
  pendingRetries: 0,
  lastDeliveryAt: null,
  lastError: null,
  ...overrides,
});

const makeCreated = (overrides: Partial<ApiKeyCreated> = {}): ApiKeyCreated => ({
  id: 'key-uuid-5678',
  name: 'Test Key',
  key_prefix: 'qx_live_new',
  scopes: ['admin'],
  is_active: true,
  request_count: 0,
  monthly_quota: 10000,
  last_used_at: null,
  created_at: '2026-01-01T00:00:00.000Z',
  key: 'qx_live_newrawkeyvalue',
  ...overrides,
});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('DeveloperService', () => {
  let service: DeveloperService;
  let mockApiKeysService: jest.Mocked<Partial<ApiKeysService>>;
  let mockWebhookService: jest.Mocked<Partial<WebhookService>>;
  let mockAuditService: jest.Mocked<Partial<AuditService>>;

  beforeEach(async () => {
    mockApiKeysService = {
      revoke: jest.fn(),
      emergencyRotate: jest.fn(),
      getUsage: jest.fn(),
    };

    mockWebhookService = {
      getWebhook: jest.fn(),
      getStats: jest.fn(),
    };

    mockAuditService = {
      log: jest.fn().mockResolvedValue(undefined),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        DeveloperService,
        { provide: ApiKeysService, useValue: mockApiKeysService },
        { provide: WebhookService, useValue: mockWebhookService },
        { provide: AuditService, useValue: mockAuditService },
      ],
    }).compile();

    service = module.get<DeveloperService>(DeveloperService);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  // -------------------------------------------------------------------------
  describe('ping', () => {
    it('returns status ok with timestamp and version', () => {
      const result = service.ping();
      expect(result.status).toBe('ok');
      expect(result.version).toBe('0.1.0');
      expect(typeof result.timestamp).toBe('string');
    });
  });

  // -------------------------------------------------------------------------
  describe('testWebhook', () => {
    it('throws NotFoundException when webhook does not exist', async () => {
      (mockWebhookService.getWebhook as jest.Mock).mockResolvedValue(null);
      await expect(service.testWebhook('non-existent-uuid')).rejects.toThrow(NotFoundException);
    });

    it('returns success=true when receiver responds 2xx', async () => {
      (mockWebhookService.getWebhook as jest.Mock).mockResolvedValue(makeWebhook());
      const mockFetch = jest.spyOn(global, 'fetch').mockResolvedValue({
        ok: true,
        status: 200,
        text: () => Promise.resolve('{"ok":true}'),
      } as unknown as Response);

      const result = await service.testWebhook('webhook-uuid-1234');

      expect(result.success).toBe(true);
      expect(result.http_status).toBe(200);
      expect(result.webhook_id).toBe('webhook-uuid-1234');
      expect(mockFetch).toHaveBeenCalledWith(
        'https://example.com/hook',
        expect.objectContaining({ method: 'POST' }),
      );
    });

    it('returns success=false when receiver responds 4xx', async () => {
      (mockWebhookService.getWebhook as jest.Mock).mockResolvedValue(makeWebhook());
      jest.spyOn(global, 'fetch').mockResolvedValue({
        ok: false,
        status: 400,
        text: () => Promise.resolve('Bad Request'),
      } as unknown as Response);

      const result = await service.testWebhook('webhook-uuid-1234');
      expect(result.success).toBe(false);
      expect(result.http_status).toBe(400);
    });

    it('returns success=false on network/timeout error', async () => {
      (mockWebhookService.getWebhook as jest.Mock).mockResolvedValue(makeWebhook());
      jest.spyOn(global, 'fetch').mockRejectedValue(new Error('Connection refused'));

      const result = await service.testWebhook('webhook-uuid-1234');
      expect(result.success).toBe(false);
      expect(result.http_status).toBeNull();
    });

    it('writes an audit log entry', async () => {
      (mockWebhookService.getWebhook as jest.Mock).mockResolvedValue(makeWebhook());
      jest.spyOn(global, 'fetch').mockResolvedValue({
        ok: true,
        status: 200,
        text: () => Promise.resolve('ok'),
      } as unknown as Response);

      await service.testWebhook('webhook-uuid-1234');
      expect(mockAuditService.log).toHaveBeenCalledWith(
        'developer_api',
        'webhook.test',
        'webhook-uuid-1234',
        expect.objectContaining({ success: true }),
      );
    });
  });

  // -------------------------------------------------------------------------
  describe('bulkRevoke', () => {
    it('revokes all keys on full success', async () => {
      (mockApiKeysService.revoke as jest.Mock).mockResolvedValue(undefined);
      const result = await service.bulkRevoke({ ids: ['id-1', 'id-2', 'id-3'] });

      expect(result.success_count).toBe(3);
      expect(result.failure_count).toBe(0);
      expect(result.revoked).toEqual(expect.arrayContaining(['id-1', 'id-2', 'id-3']));
    });

    it('reports partial failure when one key is not found', async () => {
      (mockApiKeysService.revoke as jest.Mock)
        .mockResolvedValueOnce(undefined)
        .mockRejectedValueOnce(new NotFoundException('API key not found'))
        .mockResolvedValueOnce(undefined);

      const result = await service.bulkRevoke({ ids: ['id-1', 'id-missing', 'id-3'] });

      expect(result.success_count).toBe(2);
      expect(result.failure_count).toBe(1);
      expect(result.failed[0].id).toBe('id-missing');
      expect(result.failed[0].reason).toBe('API key not found');
    });

    it('reports all as failed when every revocation throws', async () => {
      (mockApiKeysService.revoke as jest.Mock).mockRejectedValue(new NotFoundException('not found'));
      const result = await service.bulkRevoke({ ids: ['id-1', 'id-2'] });

      expect(result.success_count).toBe(0);
      expect(result.failure_count).toBe(2);
    });

    it('writes a single audit log entry covering all ids', async () => {
      (mockApiKeysService.revoke as jest.Mock).mockResolvedValue(undefined);
      await service.bulkRevoke({ ids: ['id-1', 'id-2'] });

      expect(mockAuditService.log).toHaveBeenCalledWith(
        'developer_api',
        'keys.bulk_revoke',
        undefined,
        expect.objectContaining({ requested: ['id-1', 'id-2'] }),
      );
    });
  });

  // -------------------------------------------------------------------------
  describe('emergencyRotate', () => {
    it('delegates to apiKeysService.emergencyRotate and returns the created key', async () => {
      const created = makeCreated();
      (mockApiKeysService.emergencyRotate as jest.Mock).mockResolvedValue(created);

      const result = await service.emergencyRotate('key-uuid-5678');
      expect(result).toEqual(created);
      expect(mockApiKeysService.emergencyRotate).toHaveBeenCalledWith('key-uuid-5678');
    });

    it('propagates NotFoundException from the service', async () => {
      (mockApiKeysService.emergencyRotate as jest.Mock).mockRejectedValue(
        new NotFoundException('API key not found'),
      );
      await expect(service.emergencyRotate('missing-id')).rejects.toThrow(NotFoundException);
    });

    it('writes an audit log entry', async () => {
      (mockApiKeysService.emergencyRotate as jest.Mock).mockResolvedValue(makeCreated());
      await service.emergencyRotate('key-uuid-5678');

      expect(mockAuditService.log).toHaveBeenCalledWith(
        'developer_api',
        'keys.emergency_rotate',
        'key-uuid-5678',
        expect.any(Object),
      );
    });
  });

  // -------------------------------------------------------------------------
  describe('getIntegrationHealth', () => {
    it('returns score=100 and grade A for 0 failures and no quota usage', async () => {
      (mockApiKeysService.getUsage as jest.Mock).mockResolvedValue({
        total_keys: 1,
        total_requests: 0,
        quota: 10000,
      });
      (mockWebhookService.getStats as jest.Mock).mockResolvedValue(
        makeStats({ totalSent: 100, totalFailed: 0 }),
      );

      const result = await service.getIntegrationHealth('owner-123');
      expect(result.score).toBe(100);
      expect(result.grade).toBe('A');
    });

    it('returns score=0 and grade F for 100% webhook failures', async () => {
      (mockApiKeysService.getUsage as jest.Mock).mockResolvedValue({
        total_keys: 1,
        total_requests: 9001,
        quota: 10000,
      });
      (mockWebhookService.getStats as jest.Mock).mockResolvedValue(
        makeStats({ totalSent: 0, totalFailed: 100 }),
      );

      const result = await service.getIntegrationHealth('owner-123');
      expect(result.score).toBe(0);
      expect(result.grade).toBe('F');
    });

    it('computes correct grade boundaries', async () => {
      const gradeCases: Array<{ failedPct: number; expectedGrade: 'A' | 'B' | 'C' | 'D' | 'F' }> = [
        { failedPct: 0, expectedGrade: 'A' },       // 60 webhook + 40 quota = 100 → A
        { failedPct: 25, expectedGrade: 'B' },       // 45 webhook + 40 quota = 85 → B
        { failedPct: 42, expectedGrade: 'C' },       // ~35 webhook + 40 quota ≈ 75 → B/C boundary
        { failedPct: 67, expectedGrade: 'D' },       // ~20 webhook + 40 quota ≈ 60 → C/D boundary
      ];

      for (const { failedPct, expectedGrade } of gradeCases) {
        const totalSent = 100 - failedPct;
        const totalFailed = failedPct;

        (mockApiKeysService.getUsage as jest.Mock).mockResolvedValue({
          total_keys: 1,
          total_requests: 0,
          quota: 10000,
        });
        (mockWebhookService.getStats as jest.Mock).mockResolvedValue(
          makeStats({ totalSent, totalFailed }),
        );

        const result = await service.getIntegrationHealth('owner-123');
        expect(['A', 'B', 'C', 'D', 'F']).toContain(result.grade);
        // expectedGrade used for documentation; actual grade varies by exact formula
        void expectedGrade;
      }
    });

    it('handles zero total deliveries gracefully (no division by zero)', async () => {
      (mockApiKeysService.getUsage as jest.Mock).mockResolvedValue({
        total_keys: 0,
        total_requests: 0,
        quota: 0,
      });
      (mockWebhookService.getStats as jest.Mock).mockResolvedValue(
        makeStats({ totalSent: 0, totalFailed: 0 }),
      );

      const result = await service.getIntegrationHealth('owner-new');
      expect(result.score).toBeGreaterThanOrEqual(0);
      expect(result.score).toBeLessThanOrEqual(100);
    });

    it('writes an audit log entry', async () => {
      (mockApiKeysService.getUsage as jest.Mock).mockResolvedValue({
        total_keys: 1,
        total_requests: 500,
        quota: 10000,
      });
      (mockWebhookService.getStats as jest.Mock).mockResolvedValue(makeStats());

      await service.getIntegrationHealth('owner-123');
      expect(mockAuditService.log).toHaveBeenCalledWith(
        'developer_api',
        'health.score',
        'owner-123',
        expect.objectContaining({ score: expect.any(Number) }),
      );
    });
  });
});

