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
});
