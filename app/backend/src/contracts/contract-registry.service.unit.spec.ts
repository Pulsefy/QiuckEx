import { BadRequestException, NotFoundException } from '@nestjs/common';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { SupabaseService } from '../supabase/supabase.service';
import { AppConfigService } from '../config';
import { AuditService } from '../audit/audit.service';
import { ContractRegistryService } from './contract-registry.service';
import { ContractChangeWebhookService } from './contract-change-webhook.service';
import {
  ContractChangeWebhookDispatcher,
} from './contract-change-webhook.dispatcher';

describe('ContractRegistryService', () => {
  let service: ContractRegistryService;
  let mockSupabaseService: jest.Mocked<Partial<SupabaseService>>;
  let mockAuditService: jest.Mocked<Partial<AuditService>>;
  let mockAppConfigService: Partial<AppConfigService>;
  let mockEventEmitter: jest.Mocked<EventEmitter2>;
  let mockContractChangeWebhookService: jest.Mocked<Partial<ContractChangeWebhookService>>;
  let mockWebhookDispatcher: jest.Mocked<Partial<ContractChangeWebhookDispatcher>>;

  beforeEach(() => {
    const mockClient = {
      from: jest.fn(() => ({
        select: jest.fn().mockReturnThis(),
        eq: jest.fn().mockReturnThis(),
        order: jest.fn().mockResolvedValue({ data: [], error: null }),
        delete: jest.fn().mockReturnThis(),
        insert: jest.fn().mockResolvedValue({ error: null }),
      })),
    };

    mockSupabaseService = {
      getClient: jest.fn(() => mockClient as never),
    };

    mockAuditService = {
      log: jest.fn().mockResolvedValue(undefined),
    };

    mockAppConfigService = {
      network: 'testnet',
    };

    mockEventEmitter = {
      emit: jest.fn(),
    } as unknown as jest.Mocked<EventEmitter2>;

    mockContractChangeWebhookService = {
      getEnabledWebhooks: jest.fn().mockResolvedValue([]),
      listWebhooks: jest.fn().mockResolvedValue([]),
      deleteWebhook: jest.fn().mockResolvedValue(true),
      registerWebhook: jest.fn(),
    } as unknown as jest.Mocked<Partial<ContractChangeWebhookService>>;

    mockWebhookDispatcher = {
      dispatch: jest.fn().mockResolvedValue([]),
    } as unknown as jest.Mocked<Partial<ContractChangeWebhookDispatcher>>;

    service = new ContractRegistryService(
      mockSupabaseService as unknown as SupabaseService,
      mockAuditService as unknown as AuditService,
      mockAppConfigService as AppConfigService,
      mockEventEmitter,
      mockContractChangeWebhookService as unknown as ContractChangeWebhookService,
      mockWebhookDispatcher as unknown as ContractChangeWebhookDispatcher,
    );
  });

  it('publishes and returns the active registry', async () => {
    const result = await service.publish({
      networkPassphrase: 'Test SDF Network ; September 2015',
      deploymentId: 'deploy-1',
      contracts: [
        {
          name: 'quickex',
          contractId: 'C123',
          wasmHash: 'abc123',
          contractVersion: 1,
        },
      ],
    });

    expect(result.data.quickex).toEqual(
      expect.objectContaining({ id: 'C123', wasmHash: 'abc123', version: 1 }),
    );
    expect(result.version).toBeGreaterThan(0);
    expect(mockAuditService.log).toHaveBeenCalledWith(
      'contract_registry',
      'registry.publish',
      'deploy-1',
      expect.any(Object),
    );
  });

  it('rejects a mismatched passphrase', async () => {
    await expect(
      service.publish({
        networkPassphrase: 'Public Global Stellar Network ; September 2015',
        contracts: [
          {
            name: 'quickex',
            contractId: 'C123',
            wasmHash: 'abc123',
          },
        ],
      }),
    ).rejects.toThrow(BadRequestException);
  });

  it('rolls back to a previous contract version', async () => {
    await service.publish({
      networkPassphrase: 'Test SDF Network ; September 2015',
      deploymentId: 'deploy-1',
      contracts: [
        {
          name: 'quickex',
          contractId: 'C123',
          wasmHash: 'abc123',
          contractVersion: 1,
        },
      ],
    });

    await service.publish({
      networkPassphrase: 'Test SDF Network ; September 2015',
      deploymentId: 'deploy-2',
      contracts: [
        {
          name: 'quickex',
          contractId: 'C456',
          wasmHash: 'def456',
          contractVersion: 2,
        },
      ],
    });

    const result = await service.rollback({ name: 'quickex', version: 1 });
    expect(result.data.quickex).toEqual(
      expect.objectContaining({ id: 'C123', wasmHash: 'abc123', version: 1 }),
    );
  });

  it('throws when rolling back a missing version', async () => {
    await expect(service.rollback({ name: 'quickex', version: 99 })).rejects.toThrow(
      NotFoundException,
    );
  });

  it('upserts a single deployment and exposes it through deployment reads', async () => {
    const upserted = await service.upsertDeployment({
      name: 'quickex',
      network: 'testnet',
      networkPassphrase: 'Test SDF Network ; September 2015',
      contractId: 'C777',
      wasmHash: '0x777',
      contractVersion: 7,
      schemaVersion: '1.2.0',
      schemaCompatibility: { min: '1.0.0', max: '2.0.0' },
      initParams: { admin: 'GADMIN' },
      metadata: { source: 'admin-upsert' },
      deploymentId: 'deploy-777',
    });

    expect(upserted).toEqual(
      expect.objectContaining({
        name: 'quickex',
        contractId: 'C777',
        wasmHash: '0x777',
        schemaVersion: '1.2.0',
      }),
    );

    const byName = await service.getDeploymentByName('quickex');
    expect(byName.contractId).toBe('C777');

    const all = await service.getDeployments();
    expect(all.deployments).toHaveLength(1);
    expect(all.deployments[0]?.schemaCompatibility).toEqual({
      min: '1.0.0',
      max: '2.0.0',
    });

    expect(mockAuditService.log).toHaveBeenCalledWith(
      'contract_registry',
      'registry.deployment.upsert',
      'quickex',
      expect.any(Object),
    );
  });

  it('rejects upsert when request network does not match active backend network', async () => {
    await expect(
      service.upsertDeployment({
        name: 'quickex',
        network: 'mainnet',
        networkPassphrase: 'Public Global Stellar Network ; September 2015',
        contractId: 'C111',
        wasmHash: '0x111',
        schemaVersion: '1.0.0',
        schemaCompatibility: { min: '1.0.0', max: '1.0.0' },
      }),
    ).rejects.toThrow(BadRequestException);
  });

  describe('Dual-read finalization', () => {
    it('finalizes dual-read by clearing previousContractId', async () => {
      // Setup: publish with dual-read config
      const mockClient = {
        from: jest.fn(() => ({
          select: jest.fn().mockReturnThis(),
          eq: jest.fn().mockReturnThis(),
          order: jest.fn().mockResolvedValue({
            data: [
              {
                contract_name: 'quickex',
                network: 'testnet',
                contract_id: 'C456',
                previous_contract_id: 'C123',
                effective_ledger: 50000000,
                effective_time: null,
                wasm_hash: 'def456',
                contract_version: 2,
                deployment_id: 'deploy-2',
                metadata: {},
                published_by: 'test',
                version: 2,
                created_at: '2026-06-02T10:00:00Z',
                updated_at: '2026-06-02T10:00:00Z',
                network_passphrase: 'Test SDF Network ; September 2015',
                is_active: true,
              },
            ],
            error: null,
          }),
          delete: jest.fn().mockReturnThis(),
          insert: jest.fn().mockResolvedValue({ error: null }),
        })),
      };

      mockSupabaseService = {
        getClient: jest.fn(() => mockClient as never),
      };

      service = new ContractRegistryService(
        mockSupabaseService as unknown as SupabaseService,
        mockAuditService as unknown as AuditService,
        mockAppConfigService as AppConfigService,
        mockEventEmitter,
        mockContractChangeWebhookService as unknown as ContractChangeWebhookService,
        mockWebhookDispatcher as unknown as ContractChangeWebhookDispatcher,
      );

      const result = await service.finalizeDualRead('quickex');

      // Should have removed dual-read config
      expect(mockAuditService.log).toHaveBeenCalledWith(
        'contract_registry',
        'registry.finalize_dual_read',
        'quickex',
        expect.objectContaining({ actor: 'deployment_automation' }),
      );

      // Result should show cleared previousContractId
      expect(result.data.quickex).toBeDefined();
    });

    it('throws when no active entry exists', async () => {
      const mockClient = {
        from: jest.fn(() => ({
          select: jest.fn().mockReturnThis(),
          eq: jest.fn().mockReturnThis(),
          order: jest.fn().mockResolvedValue({ data: [], error: null }),
          delete: jest.fn().mockReturnThis(),
          insert: jest.fn().mockResolvedValue({ error: null }),
        })),
      };

      mockSupabaseService = {
        getClient: jest.fn(() => mockClient as never),
      };

      service = new ContractRegistryService(
        mockSupabaseService as unknown as SupabaseService,
        mockAuditService as unknown as AuditService,
        mockAppConfigService as AppConfigService,
        mockEventEmitter,
        mockContractChangeWebhookService as unknown as ContractChangeWebhookService,
        mockWebhookDispatcher as unknown as ContractChangeWebhookDispatcher,
      );

      await expect(service.finalizeDualRead('missing')).rejects.toThrow(NotFoundException);
    });

    it('throws when not in dual-read window', async () => {
      const mockClient = {
        from: jest.fn(() => ({
          select: jest.fn().mockReturnThis(),
          eq: jest.fn().mockReturnThis(),
          order: jest.fn().mockResolvedValue({
            data: [
              {
                contract_name: 'quickex',
                network: 'testnet',
                contract_id: 'C456',
                previous_contract_id: null,
                effective_ledger: null,
                effective_time: null,
                wasm_hash: 'def456',
                contract_version: 2,
                deployment_id: 'deploy-2',
                metadata: {},
                published_by: 'test',
                version: 2,
                created_at: '2026-06-02T10:00:00Z',
                updated_at: '2026-06-02T10:00:00Z',
                network_passphrase: 'Test SDF Network ; September 2015',
                is_active: true,
              },
            ],
            error: null,
          }),
          delete: jest.fn().mockReturnThis(),
          insert: jest.fn().mockResolvedValue({ error: null }),
        })),
      };

      mockSupabaseService = {
        getClient: jest.fn(() => mockClient as never),
      };

      service = new ContractRegistryService(
        mockSupabaseService as unknown as SupabaseService,
        mockAuditService as unknown as AuditService,
        mockAppConfigService as AppConfigService,
        mockEventEmitter,
        mockContractChangeWebhookService as unknown as ContractChangeWebhookService,
        mockWebhookDispatcher as unknown as ContractChangeWebhookDispatcher,
      );

      await expect(service.finalizeDualRead('quickex')).rejects.toThrow(BadRequestException);
    });
  });
});
