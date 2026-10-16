import { HttpStatus } from '@nestjs/common';
import { Request, Response } from 'express';
import { ContractRegistryController } from './contract-registry.controller';
import { ContractRegistryService } from './contract-registry.service';
import { ContractCompatibilityService } from './contract-compatibility.service';

describe('ContractRegistryController (unit)', () => {
  let controller: ContractRegistryController;
  let mockRegistryService: jest.Mocked<Partial<ContractRegistryService>>;
  let mockCompatibilityService: jest.Mocked<Partial<ContractCompatibilityService>>;

  beforeEach(() => {
    mockRegistryService = {
      getDeployments: jest.fn().mockResolvedValue({
        network: 'testnet',
        deployments: [],
      }),
      getDeploymentByName: jest.fn().mockResolvedValue({
        name: 'quickex',
        id: 'CD2J6K7T3YJ77QXZP3ACTIVE',
        version: 1,
        schemaVersion: '1.0.0',
      }),
      getRegistry: jest.fn().mockResolvedValue({
        network: 'testnet',
        etag: 'w/"test-etag"',
        data: {},
      }),
      publish: jest.fn().mockResolvedValue({ success: true }),
      upsertDeployment: jest.fn().mockResolvedValue({ name: 'quickex' }),
      rollback: jest.fn().mockResolvedValue({ success: true }),
    };

    mockCompatibilityService = {
      getCompatibilityMetadata: jest.fn().mockResolvedValue({
        contractName: 'quickex',
        network: 'testnet',
        contractId: 'CD2J6K7T3YJ77QXZP3ACTIVE',
        contractVersion: 1,
        schemaVersion: '1.0.0',
        schemaCompatibility: { min: '1.0.0', max: '2.0.0' },
        flow: 'pay_initiation',
        compatible: true,
      }),
      validateWriteCompatibility: jest.fn().mockResolvedValue({
        contractName: 'quickex',
        network: 'testnet',
        contractId: 'CD2J6K7T3YJ77QXZP3ACTIVE',
        contractVersion: 1,
        schemaVersion: '1.0.0',
        schemaCompatibility: { min: '1.0.0', max: '2.0.0' },
        flow: 'pay_initiation',
        compatible: true,
      }),
    };

    controller = new ContractRegistryController(
      mockRegistryService as unknown as ContractRegistryService,
      mockCompatibilityService as unknown as ContractCompatibilityService,
    );
  });

  describe('GET registry/compatibility', () => {
    it('calls getCompatibilityMetadata with provided flow and contract name', async () => {
      const result = await controller.getCompatibility('link', 'quickex');
      expect(mockCompatibilityService.getCompatibilityMetadata).toHaveBeenCalledWith(
        'link',
        'quickex',
      );
      expect(result).toHaveProperty('compatible', true);
    });

    it('defaults to pay_initiation and quickex when omitted', async () => {
      await controller.getCompatibility(undefined, undefined);
      expect(mockCompatibilityService.getCompatibilityMetadata).toHaveBeenCalledWith(
        'pay_initiation',
        'quickex',
      );
    });
  });

  describe('POST registry/compatibility/validate', () => {
    it('delegates validation to compatibilityService', async () => {
      const input = {
        flow: 'quote' as const,
        contractName: 'quickex',
        contractVersion: 1,
        schemaVersion: '1.0.0',
      };
      const result = await controller.validateCompatibility(input);
      expect(mockCompatibilityService.validateWriteCompatibility).toHaveBeenCalledWith(input);
      expect(result).toHaveProperty('compatible', true);
    });
  });

  describe('GET registry with ETag', () => {
    it('sets ETag header and returns full registry when If-None-Match does not match', async () => {
      const req = { headers: {} } as Request;
      const res = {
        setHeader: jest.fn(),
        status: jest.fn(),
      } as unknown as Response;

      const result = await controller.getRegistry(req, res);
      expect(res.setHeader).toHaveBeenCalledWith('ETag', 'w/"test-etag"');
      expect(result).toEqual(
        expect.objectContaining({
          etag: 'w/"test-etag"',
        }),
      );
    });

    it('returns 304 Not Modified when client ETag matches', async () => {
      const req = {
        headers: { 'if-none-match': 'w/"test-etag"' },
      } as unknown as Request;
      const res = {
        setHeader: jest.fn(),
        status: jest.fn(),
      } as unknown as Response;

      const result = await controller.getRegistry(req, res);
      expect(res.status).toHaveBeenCalledWith(HttpStatus.NOT_MODIFIED);
      expect(result).toBeUndefined();
    });
  });
});
