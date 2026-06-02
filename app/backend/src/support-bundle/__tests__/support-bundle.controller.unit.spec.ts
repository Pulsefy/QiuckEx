import { Test, TestingModule } from '@nestjs/testing';
import { SupportBundleController } from '../support-bundle.controller';
import { SupportBundleService } from '../support-bundle.service';
import { SupportBundleDto } from '../dto/support-bundle.dto';

describe('SupportBundleController', () => {
  let controller: SupportBundleController;
  let service: jest.Mocked<SupportBundleService>;

  const mockBundle: SupportBundleDto = {
    metadata: {
      version: '1.0',
      generated_at: '2026-06-02T12:34:56Z',
      network: 'testnet',
      bundle_size_bytes: 1000,
    },
    network_config: {
      network: 'testnet',
      network_passphrase: 'Test SDF Network ; September 2015',
    },
    contract_registry: {
      active_contracts: [
        {
          name: 'quickex',
          contract_id: 'CD2J6K7T3YJ77QXZP3EXAMPLE',
          version: 1,
          wasm_hash: 'abcd...',
          updated_at: '2026-06-01T10:00:00Z',
        },
      ],
    },
    indexer_status: {
      current_network_ledger: 50000000,
      last_indexed_ledger: 49999500,
      lag_ledgers: 500,
      is_lagging: false,
      status: 'HEALTHY',
    },
    checkpoints: [
      {
        contract_id: 'CD2J6K7T3YJ77QXZP3EXAMPLE',
        last_ledger: 49999500,
        updated_at: '2026-06-02T12:30:00Z',
      },
    ],
    recent_errors: [
      {
        timestamp: '2026-06-02T12:20:00Z',
        action: 'test.action',
        actor: '[REDACTED]',
        error_summary: 'Test error',
      },
    ],
  };

  beforeEach(async () => {
    const mockService = {
      generateBundle: jest.fn().mockResolvedValue(mockBundle),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [SupportBundleController],
      providers: [
        {
          provide: SupportBundleService,
          useValue: mockService,
        },
      ],
    }).compile();

    controller = module.get<SupportBundleController>(SupportBundleController);
    service = module.get(SupportBundleService) as jest.Mocked<SupportBundleService>;
  });

  describe('generateBundle', () => {
    it('should return support bundle without request IDs by default', async () => {
      const result = await controller.generateBundle(false);

      expect(result).toEqual(mockBundle);
      expect(service.generateBundle).toHaveBeenCalledWith(false);
    });

    it('should return support bundle with request IDs when requested', async () => {
      const bundleWithRequestIds = {
        ...mockBundle,
        recent_errors: [
          {
            ...mockBundle.recent_errors[0],
            request_id: 'req-12345',
          },
        ],
      };

      service.generateBundle.mockResolvedValue(bundleWithRequestIds);

      const result = await controller.generateBundle(true);

      expect(result).toEqual(bundleWithRequestIds);
      expect(service.generateBundle).toHaveBeenCalledWith(true);
    });

    it('should handle service errors gracefully', async () => {
      service.generateBundle.mockRejectedValue(new Error('Generation failed'));

      await expect(controller.generateBundle(false)).rejects.toThrow('Generation failed');
    });
  });

  describe('request handling', () => {
    it('should parse includeRequestIds as boolean', async () => {
      await controller.generateBundle(true);
      expect(service.generateBundle).toHaveBeenCalledWith(true);

      await controller.generateBundle(false);
      expect(service.generateBundle).toHaveBeenCalledWith(false);
    });

    it('should default to false for includeRequestIds', async () => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      await controller.generateBundle(undefined as unknown as boolean);
      expect(service.generateBundle).toHaveBeenCalledWith(false);
    });
  });

  describe('response validation', () => {
    it('should return valid bundle structure', async () => {
      const result = await controller.generateBundle(false);

      expect(result).toHaveProperty('metadata');
      expect(result).toHaveProperty('network_config');
      expect(result).toHaveProperty('contract_registry');
      expect(result).toHaveProperty('indexer_status');
      expect(result).toHaveProperty('checkpoints');
      expect(result).toHaveProperty('recent_errors');
    });

    it('should return JSON serializable response', async () => {
      const result = await controller.generateBundle(false);

      expect(() => JSON.stringify(result)).not.toThrow();
    });
  });
});
