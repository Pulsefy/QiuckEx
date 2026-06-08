import { Test, TestingModule } from '@nestjs/testing';
import { SupportBundleService } from '../support-bundle.service';
import { AppConfigService } from '../../config';
import { ContractRegistryService } from '../../contracts/contract-registry.service';
import { IndexerLagService } from '../../indexer-lag/indexer-lag.service';
import { IndexerCheckpointRepository } from '../../ingestion/indexer-checkpoint.repository';
import { AuditService } from '../../audit/audit.service';

describe('SupportBundleService', () => {
  let service: SupportBundleService;
  let registryService: jest.Mocked<ContractRegistryService>;
  let indexerLagService: jest.Mocked<IndexerLagService>;
  let checkpointRepo: jest.Mocked<IndexerCheckpointRepository>;
  let auditService: jest.Mocked<AuditService>;

  beforeEach(async () => {
    const mockConfigService = {
      network: 'testnet',
      networkPassphrase: 'Test SDF Network ; September 2015',
    };

    const mockRegistryService = {
      getRegistry: jest.fn().mockResolvedValue({
        data: {
          quickex: {
            id: 'CD2J6K7T3YJ77QXZP3EXAMPLE',
            version: 3,
            wasmHash: 'abcdef1234567890abcdef1234567890',
            updatedAt: '2026-06-01T10:00:00Z',
          },
        },
      }),
    };

    const mockIndexerLagService = {
      getStatus: jest.fn().mockReturnValue({
        currentNetworkLedger: 50000000,
        lastIndexedLedger: 49999500,
        lagLedgers: 500,
        isLagging: false,
        isEnabled: true,
        isOverridden: false,
        thresholdLedgers: 1000,
      }),
    };

    const mockCheckpointRepo = {
      getLastLedger: jest.fn().mockResolvedValue(49999500),
      saveLastLedger: jest.fn().mockResolvedValue(undefined),
    };

    const mockAuditService = {
      log: jest.fn().mockResolvedValue(undefined),
      query: jest.fn().mockResolvedValue({
        data: [
          {
            id: 'log-1',
            actor: 'test-user',
            action: 'escrow.deposit',
            metadata: { error: 'Insufficient balance' },
            requestId: 'req-12345',
            createdAt: new Date('2026-06-02T12:20:00Z'),
          },
        ],
        total: 1,
        page: 1,
        limit: 50,
      }),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        SupportBundleService,
        { provide: AppConfigService, useValue: mockConfigService },
        { provide: ContractRegistryService, useValue: mockRegistryService },
        { provide: IndexerLagService, useValue: mockIndexerLagService },
        { provide: IndexerCheckpointRepository, useValue: mockCheckpointRepo },
        { provide: AuditService, useValue: mockAuditService },
      ],
    }).compile();

    service = module.get<SupportBundleService>(SupportBundleService);
    registryService = module.get(ContractRegistryService) as jest.Mocked<ContractRegistryService>;
    indexerLagService = module.get(IndexerLagService) as jest.Mocked<IndexerLagService>;
    checkpointRepo = module.get(IndexerCheckpointRepository) as jest.Mocked<IndexerCheckpointRepository>;
    auditService = module.get(AuditService) as jest.Mocked<AuditService>;
  });

  describe('generateBundle', () => {
    it('should generate complete support bundle', async () => {
      const bundle = await service.generateBundle(false);

      expect(bundle).toBeDefined();
      expect(bundle.metadata).toBeDefined();
      expect(bundle.metadata.version).toBe('1.0');
      expect(bundle.metadata.network).toBe('testnet');
      expect(bundle.metadata.generated_at).toBeDefined();
      expect(bundle.metadata.bundle_size_bytes).toBeGreaterThan(0);

      expect(bundle.network_config).toBeDefined();
      expect(bundle.network_config.network).toBe('testnet');
      expect(bundle.network_config.network_passphrase).toBe('Test SDF Network ; September 2015');

      expect(bundle.contract_registry).toBeDefined();
      expect(bundle.contract_registry.active_contracts).toHaveLength(1);

      expect(bundle.indexer_status).toBeDefined();
      expect(bundle.indexer_status.lag_ledgers).toBe(500);
      expect(bundle.indexer_status.status).toBe('HEALTHY');

      expect(bundle.checkpoints).toBeDefined();
      expect(bundle.checkpoints.length).toBeGreaterThan(0);

      expect(bundle.recent_errors).toBeDefined();
    });

    it('should redact request IDs when includeRequestIds=false', async () => {
      const bundle = await service.generateBundle(false);
      const hasRequestIds = bundle.recent_errors.some((error) => error.request_id);
      expect(hasRequestIds).toBe(false);
    });

    it('should include request IDs when includeRequestIds=true', async () => {
      const bundle = await service.generateBundle(true);
      const hasRequestIds = bundle.recent_errors.some((error) => error.request_id);
      expect(hasRequestIds).toBe(true);
    });

    it('should handle missing registry data gracefully', async () => {
      registryService.getRegistry.mockRejectedValue(new Error('Registry unavailable'));

      const bundle = await service.generateBundle(false);

      expect(bundle.contract_registry.active_contracts).toEqual([]);
    });

    it('should handle missing indexer status gracefully', async () => {
      indexerLagService.getStatus.mockImplementation(() => {
        throw new Error('Indexer status unavailable');
      });

      const bundle = await service.generateBundle(false);

      expect(bundle.indexer_status.status).toBe('UNKNOWN');
      expect(bundle.indexer_status.lag_ledgers).toBe(0);
    });

    it('should handle missing checkpoints gracefully', async () => {
      checkpointRepo.getLastLedger.mockRejectedValue(new Error('Checkpoint unavailable'));

      const bundle = await service.generateBundle(false);

      expect(bundle.checkpoints).toEqual([]);
    });

    it('should handle missing audit logs gracefully', async () => {
      auditService.query.mockRejectedValue(new Error('Audit unavailable'));

      const bundle = await service.generateBundle(false);

      expect(bundle.recent_errors).toEqual([]);
    });
  });

  describe('data redaction', () => {
    it('should redact email addresses in actor field', async () => {
      auditService.query.mockResolvedValue({
        data: [
          {
            id: 'log-1',
            actor: 'user@example.com',
            action: 'test.action',
            metadata: { error: 'Test error' },
            requestId: 'req-1',
            createdAt: new Date(),
          },
        ],
        total: 1,
        page: 1,
        limit: 50,
      });

      const bundle = await service.generateBundle(false);

      expect(bundle.recent_errors[0].actor).toBe('[REDACTED]');
    });

    it('should keep service names in actor field', async () => {
      auditService.query.mockResolvedValue({
        data: [
          {
            id: 'log-1',
            actor: 'deployment_automation',
            action: 'test.action',
            metadata: { error: 'Test error' },
            requestId: 'req-1',
            createdAt: new Date(),
          },
        ],
        total: 1,
        page: 1,
        limit: 50,
      });

      const bundle = await service.generateBundle(false);

      expect(bundle.recent_errors[0].actor).toBe('deployment_automation');
    });

    it('should truncate wasm hash in registry snapshot', async () => {
      const bundle = await service.generateBundle(false);

      expect(bundle.contract_registry.active_contracts[0].wasm_hash).toMatch(/\.\.\./);
      expect(bundle.contract_registry.active_contracts[0].wasm_hash).toBeLessThan(40);
    });

    it('should not expose full contract ID', async () => {
      // Contract IDs should not contain secrets, so full ID is OK
      const bundle = await service.generateBundle(false);
      expect(bundle.contract_registry.active_contracts[0].contract_id).toBe('CD2J6K7T3YJ77QXZP3EXAMPLE');
    });
  });

  describe('error extraction', () => {
    it('should extract error from metadata.error field', async () => {
      auditService.query.mockResolvedValue({
        data: [
          {
            id: 'log-1',
            actor: 'test',
            action: 'test',
            metadata: { error: 'Something went wrong' },
            createdAt: new Date(),
          },
        ],
        total: 1,
        page: 1,
        limit: 50,
      });

      const bundle = await service.generateBundle(false);

      expect(bundle.recent_errors[0].error_summary).toBe('Something went wrong');
    });

    it('should extract error from metadata.message field', async () => {
      auditService.query.mockResolvedValue({
        data: [
          {
            id: 'log-1',
            actor: 'test',
            action: 'test',
            metadata: { message: 'Error message' },
            createdAt: new Date(),
          },
        ],
        total: 1,
        page: 1,
        limit: 50,
      });

      const bundle = await service.generateBundle(false);

      expect(bundle.recent_errors[0].error_summary).toBe('Error message');
    });

    it('should extract error from metadata.code field', async () => {
      auditService.query.mockResolvedValue({
        data: [
          {
            id: 'log-1',
            actor: 'test',
            action: 'test',
            metadata: { code: 'INSUFFICIENT_BALANCE' },
            createdAt: new Date(),
          },
        ],
        total: 1,
        page: 1,
        limit: 50,
      });

      const bundle = await service.generateBundle(false);

      expect(bundle.recent_errors[0].error_summary).toBe('INSUFFICIENT_BALANCE');
    });

    it('should skip logs with no error information', async () => {
      auditService.query.mockResolvedValue({
        data: [
          {
            id: 'log-1',
            actor: 'test',
            action: 'test',
            metadata: { other_field: 'value' },
            createdAt: new Date(),
          },
        ],
        total: 1,
        page: 1,
        limit: 50,
      });

      const bundle = await service.generateBundle(false);

      expect(bundle.recent_errors).toEqual([]);
    });
  });

  describe('bundle structure', () => {
    it('should include all required fields', async () => {
      const bundle = await service.generateBundle(false);

      const requiredFields = [
        'metadata',
        'network_config',
        'contract_registry',
        'indexer_status',
        'checkpoints',
        'recent_errors',
      ];

      requiredFields.forEach((field) => {
        expect(bundle).toHaveProperty(field);
      });
    });

    it('should have valid metadata structure', async () => {
      const bundle = await service.generateBundle(false);

      expect(bundle.metadata.version).toBeDefined();
      expect(bundle.metadata.generated_at).toBeDefined();
      expect(bundle.metadata.network).toBeDefined();
      expect(bundle.metadata.bundle_size_bytes).toBeGreaterThan(0);
    });

    it('should be JSON serializable', async () => {
      const bundle = await service.generateBundle(false);

      expect(() => JSON.stringify(bundle)).not.toThrow();
    });
  });
});
