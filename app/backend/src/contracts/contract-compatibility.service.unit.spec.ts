import { ContractCompatibilityService } from './contract-compatibility.service';
import { ContractRegistryService } from './contract-registry.service';
import { ContractCompatibilityError } from './errors/contract-compatibility.errors';
import { ClientContractRequirements } from './dto/contract-compatibility.dto';

describe('ContractCompatibilityService', () => {
  let service: ContractCompatibilityService;
  let mockRegistryService: jest.Mocked<ContractRegistryService>;

  beforeEach(() => {
    mockRegistryService = {
      getRegistry: jest.fn(),
    } as unknown as jest.Mocked<ContractRegistryService>;

    service = new ContractCompatibilityService(
      mockRegistryService as unknown as ContractRegistryService,
    );
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('getEndpointRequirements', () => {
    it('should return requirements for known endpoints', () => {
      const requirements = service.getEndpointRequirements('links/metadata', 'POST');
      expect(requirements).toBeDefined();
      expect(requirements?.endpoint).toBe('links/metadata');
      expect(requirements?.method).toBe('POST');
      expect(requirements?.requirements).toHaveLength(1);
      expect(requirements?.requirements[0].name).toBe('quickex');
      expect(requirements?.requirements[0].minVersion).toBe(1);
    });

    it('should return undefined for unknown endpoints', () => {
      const requirements = service.getEndpointRequirements('unknown/endpoint', 'GET');
      expect(requirements).toBeUndefined();
    });

    it('should differentiate between methods', () => {
      const postReq = service.getEndpointRequirements('links/metadata', 'POST');
      const getReq = service.getEndpointRequirements('links/metadata', 'GET');
      
      expect(postReq).toBeDefined();
      expect(getReq).toBeUndefined();
    });
  });

  describe('checkClientCompatibility', () => {
    it('should return compatible when deployed version meets requirements', async () => {
      mockRegistryService.getRegistry.mockResolvedValue({
        network: 'testnet',
        version: 3,
        etag: 'W/"test-3"',
        authoritative: true,
        data: {
          quickex: {
            id: 'C123',
            wasmHash: 'abc123',
            version: 3,
            deploymentId: 'deploy-1',
            updatedAt: new Date().toISOString(),
            metadata: {},
          },
        },
      });

      const requirements: ClientContractRequirements = {
        requirements: [{ name: 'quickex', minVersion: 2 }],
        clientVersion: '1.0.0',
      };

      const result = await service.checkClientCompatibility(requirements);

      expect(result.compatible).toBe(true);
      expect(result.contracts).toHaveLength(1);
      expect(result.contracts[0].compatible).toBe(true);
      expect(result.contracts[0].deployedVersion).toBe(3);
      expect(result.contracts[0].requiredMinVersion).toBe(2);
    });

    it('should return incompatible when deployed version is too low', async () => {
      mockRegistryService.getRegistry.mockResolvedValue({
        network: 'testnet',
        version: 2,
        etag: 'W/"test-2"',
        authoritative: true,
        data: {
          quickex: {
            id: 'C123',
            wasmHash: 'abc123',
            version: 2,
            deploymentId: 'deploy-1',
            updatedAt: new Date().toISOString(),
            metadata: {},
          },
        },
      });

      const requirements: ClientContractRequirements = {
        requirements: [{ name: 'quickex', minVersion: 5 }],
        clientVersion: '1.0.0',
      };

      const result = await service.checkClientCompatibility(requirements);

      expect(result.compatible).toBe(false);
      expect(result.contracts[0].compatible).toBe(false);
      expect(result.contracts[0].incompatibilityReason).toBe('CONTRACT_VERSION_TOO_LOW');
    });

    it('should return incompatible when deployed version exceeds maxVersion', async () => {
      mockRegistryService.getRegistry.mockResolvedValue({
        network: 'testnet',
        version: 5,
        etag: 'W/"test-5"',
        authoritative: true,
        data: {
          quickex: {
            id: 'C123',
            wasmHash: 'abc123',
            version: 5,
            deploymentId: 'deploy-1',
            updatedAt: new Date().toISOString(),
            metadata: {},
          },
        },
      });

      const requirements: ClientContractRequirements = {
        requirements: [{ name: 'quickex', minVersion: 1, maxVersion: 3 }],
        clientVersion: '1.0.0',
      };

      const result = await service.checkClientCompatibility(requirements);

      expect(result.compatible).toBe(false);
      expect(result.contracts[0].compatible).toBe(false);
      expect(result.contracts[0].incompatibilityReason).toBe('CONTRACT_VERSION_TOO_HIGH');
    });

    it('should return incompatible when contract not found', async () => {
      mockRegistryService.getRegistry.mockResolvedValue({
        network: 'testnet',
        version: 1,
        etag: 'W/"test-1"',
        authoritative: true,
        data: {},
      });

      const requirements: ClientContractRequirements = {
        requirements: [{ name: 'quickex', minVersion: 1 }],
        clientVersion: '1.0.0',
      };

      const result = await service.checkClientCompatibility(requirements);

      expect(result.compatible).toBe(false);
      expect(result.contracts[0].compatible).toBe(false);
      expect(result.contracts[0].incompatibilityReason).toBe('CONTRACT_NOT_FOUND');
    });

    it('should handle multiple contract requirements', async () => {
      mockRegistryService.getRegistry.mockResolvedValue({
        network: 'testnet',
        version: 3,
        etag: 'W/"test-3"',
        authoritative: true,
        data: {
          quickex: {
            id: 'C123',
            wasmHash: 'abc123',
            version: 3,
            deploymentId: 'deploy-1',
            updatedAt: new Date().toISOString(),
            metadata: {},
          },
          other: {
            id: 'C456',
            wasmHash: 'def456',
            version: 2,
            deploymentId: 'deploy-1',
            updatedAt: new Date().toISOString(),
            metadata: {},
          },
        },
      });

      const requirements: ClientContractRequirements = {
        requirements: [
          { name: 'quickex', minVersion: 2 },
          { name: 'other', minVersion: 1 },
        ],
        clientVersion: '1.0.0',
      };

      const result = await service.checkClientCompatibility(requirements);

      expect(result.compatible).toBe(true);
      expect(result.contracts).toHaveLength(2);
      expect(result.contracts.every((c) => c.compatible)).toBe(true);
    });

    it('should mark contracts as deprecated when version is in deprecatedVersions', async () => {
      mockRegistryService.getRegistry.mockResolvedValue({
        network: 'testnet',
        version: 2,
        etag: 'W/"test-2"',
        authoritative: true,
        data: {
          quickex: {
            id: 'C123',
            wasmHash: 'abc123',
            version: 1,
            deploymentId: 'deploy-1',
            updatedAt: new Date().toISOString(),
            metadata: {},
          },
        },
      });

      const requirements: ClientContractRequirements = {
        requirements: [{ 
          name: 'quickex', 
          minVersion: 1,
          deprecatedVersions: ['1'] 
        }],
        clientVersion: '1.0.0',
      };

      const result = await service.checkClientCompatibility(requirements);

      expect(result.compatible).toBe(true);
      expect(result.contracts[0].deprecated).toBe(true);
      expect(result.contracts[0].deprecationMessage).toBeDefined();
    });
  });

  describe('validateRequestCompatibility', () => {
    it('should allow requests when no requirements defined', async () => {
      const result = await service.validateRequestCompatibility(
        'unknown/endpoint',
        'POST',
      );

      expect(result.compatible).toBe(true);
      expect(result.metadata).toBeUndefined();
    });

    it('should throw when incompatible and rejectIncompatible is true', async () => {
      mockRegistryService.getRegistry.mockResolvedValue({
        network: 'testnet',
        version: 1,
        etag: 'W/"test-1"',
        authoritative: true,
        data: {
          quickex: {
            id: 'C123',
            wasmHash: 'abc123',
            version: 1,
            deploymentId: 'deploy-1',
            updatedAt: new Date().toISOString(),
            metadata: {},
          },
        },
      });

      // payments/initiate requires minVersion 2 and has rejectIncompatible: true
      await expect(
        service.validateRequestCompatibility('payments/initiate', 'POST'),
      ).rejects.toThrow(ContractCompatibilityError);
    });

    it('should not throw when incompatible but rejectIncompatible is false', async () => {
      mockRegistryService.getRegistry.mockResolvedValue({
        network: 'testnet',
        version: 1,
        etag: 'W/"test-1"',
        authoritative: true,
        data: {
          quickex: {
            id: 'C123',
            wasmHash: 'abc123',
            version: 1,
            deploymentId: 'deploy-1',
            updatedAt: new Date().toISOString(),
            metadata: {},
          },
        },
      });

      // links/metadata requires minVersion 1, but if we set a higher requirement via client
      // and rejectIncompatible is false, it should not throw
      const result = await service.validateRequestCompatibility(
        'links/metadata',
        'POST',
        { requirements: [{ name: 'quickex', minVersion: 5 }] },
      );

      expect(result.compatible).toBe(false);
    });

    it('should include metadata in response when compatible', async () => {
      mockRegistryService.getRegistry.mockResolvedValue({
        network: 'testnet',
        version: 3,
        etag: 'W/"test-3"',
        authoritative: true,
        data: {
          quickex: {
            id: 'C123',
            wasmHash: 'abc123',
            version: 3,
            deploymentId: 'deploy-1',
            updatedAt: new Date().toISOString(),
            metadata: {},
          },
        },
      });

      const result = await service.validateRequestCompatibility(
        'links/metadata',
        'POST',
      );

      expect(result.compatible).toBe(true);
      expect(result.metadata).toBeDefined();
      expect(result.metadata?.contracts).toHaveLength(1);
    });
  });

  describe('parseClientRequirementsFromHeader', () => {
    it('should parse valid JSON header', () => {
      const headerValue = JSON.stringify({
        requirements: [{ name: 'quickex', minVersion: 1 }],
        clientVersion: '1.0.0',
      });

      const result = service.parseClientRequirementsFromHeader(headerValue);

      expect(result).toBeDefined();
      expect(result?.requirements).toHaveLength(1);
      expect(result?.requirements[0].name).toBe('quickex');
      expect(result?.requirements[0].minVersion).toBe(1);
    });

    it('should return undefined for invalid JSON', () => {
      const result = service.parseClientRequirementsFromHeader('invalid json');
      expect(result).toBeUndefined();
    });

    it('should return undefined for missing requirements array', () => {
      const headerValue = JSON.stringify({ clientVersion: '1.0.0' });
      const result = service.parseClientRequirementsFromHeader(headerValue);
      expect(result).toBeUndefined();
    });

    it('should return undefined for empty header', () => {
      const result = service.parseClientRequirementsFromHeader('');
      expect(result).toBeUndefined();
    });

    it('should return undefined for undefined header', () => {
      const result = service.parseClientRequirementsFromHeader(undefined);
      expect(result).toBeUndefined();
    });
  });

  describe('registerEndpointRequirements', () => {
    it('should register new endpoint requirements', () => {
      service.registerEndpointRequirements({
        endpoint: 'custom/endpoint',
        method: 'POST',
        requirements: [{ name: 'quickex', minVersion: 3 }],
        rejectIncompatible: true,
        includeMetadata: true,
      });

      const requirements = service.getEndpointRequirements('custom/endpoint', 'POST');
      expect(requirements).toBeDefined();
      expect(requirements?.requirements[0].minVersion).toBe(3);
    });

    it('should update existing endpoint requirements', () => {
      // First register
      service.registerEndpointRequirements({
        endpoint: 'update/endpoint',
        method: 'PUT',
        requirements: [{ name: 'quickex', minVersion: 1 }],
        rejectIncompatible: false,
        includeMetadata: true,
      });

      // Update
      service.registerEndpointRequirements({
        endpoint: 'update/endpoint',
        method: 'PUT',
        requirements: [{ name: 'quickex', minVersion: 5 }],
        rejectIncompatible: true,
        includeMetadata: false,
      });

      const requirements = service.getEndpointRequirements('update/endpoint', 'PUT');
      expect(requirements?.requirements[0].minVersion).toBe(5);
      expect(requirements?.rejectIncompatible).toBe(true);
    });
  });

  describe('getAllEndpointRequirements', () => {
    it('should return all registered requirements', () => {
      const requirements = service.getAllEndpointRequirements();
      // Should include the default requirements
      expect(requirements.length).toBeGreaterThanOrEqual(4);
    });

    it('should include newly registered requirements', () => {
      const initialCount = service.getAllEndpointRequirements().length;

      service.registerEndpointRequirements({
        endpoint: 'new/endpoint',
        method: 'DELETE',
        requirements: [{ name: 'quickex', minVersion: 1 }],
        rejectIncompatible: false,
        includeMetadata: true,
      });

      const requirements = service.getAllEndpointRequirements();
      expect(requirements.length).toBe(initialCount + 1);
    });
  });
});