import { BadRequestException, ConflictException } from '@nestjs/common';
import {
  ContractCompatibilityService,
  CONTRACT_VERSION_MISMATCH_CODE,
  CONTRACT_SCHEMA_INCOMPATIBLE_CODE,
  CONTRACT_DEPLOYMENT_OUTDATED_CODE,
  INVALID_CONTRACT_SCHEMA_VERSION_CODE,
  compareSemver,
  isSemverWithinWindow,
  parseSemver,
} from './contract-compatibility.service';

describe('ContractCompatibilityService', () => {
  let service: ContractCompatibilityService;
  let mockRegistryReader: { getRegistry: jest.Mock };
  let mockConfigReader: { network: string; quickexContractId: string };

  const defaultDeployment = {
    id: 'CD2J6K7T3YJ77QXZP3ACTIVE',
    version: 2,
    schemaVersion: '1.2.0',
    wasmHash: '0xabc123',
    schemaCompatibility: { min: '1.0.0', max: '2.0.0' },
  };

  beforeEach(() => {
    mockConfigReader = {
      network: 'testnet',
      quickexContractId: 'CD2J6K7T3YJ77QXZP3ACTIVE',
    };

    mockRegistryReader = {
      getRegistry: jest.fn().mockResolvedValue({
        network: 'testnet',
        etag: 'w/"v2"',
        data: {
          quickex: { ...defaultDeployment },
        },
      }),
    };

    service = new ContractCompatibilityService(
      mockRegistryReader,
      mockConfigReader,
    );
  });

  describe('Semver utilities', () => {
    it('parses valid semantic version strings', () => {
      expect(parseSemver('1.0.0')).toEqual([1, 0, 0]);
      expect(parseSemver('2.15.3')).toEqual([2, 15, 3]);
      expect(parseSemver('invalid')).toBeNull();
      expect(parseSemver('1.0')).toBeNull();
      expect(parseSemver('')).toBeNull();
    });

    it('compares semantic version strings correctly', () => {
      expect(compareSemver('1.0.0', '1.0.0')).toBe(0);
      expect(compareSemver('1.1.0', '1.0.0')).toBe(1);
      expect(compareSemver('1.0.0', '1.1.0')).toBe(-1);
      expect(compareSemver('2.0.0', '1.9.9')).toBe(1);
      expect(compareSemver('1.0.5', '1.0.10')).toBe(-1);
    });

    it('throws BadRequestException on comparing invalid semver', () => {
      expect(() => compareSemver('1.0', '1.0.0')).toThrow(BadRequestException);
      try {
        compareSemver('invalid', '1.0.0');
      } catch (err) {
        expect((err as BadRequestException).getResponse()).toMatchObject({
          code: INVALID_CONTRACT_SCHEMA_VERSION_CODE,
        });
      }
    });

    it('evaluates whether a version is within a compatibility window', () => {
      const window = { min: '1.0.0', max: '2.0.0' };
      expect(isSemverWithinWindow('1.0.0', window)).toBe(true);
      expect(isSemverWithinWindow('1.5.0', window)).toBe(true);
      expect(isSemverWithinWindow('2.0.0', window)).toBe(true);
      expect(isSemverWithinWindow('0.9.9', window)).toBe(false);
      expect(isSemverWithinWindow('2.0.1', window)).toBe(false);
    });
  });

  describe('Flow compatibility requirements', () => {
    it('returns defined flow requirements for link flow', () => {
      const req = service.getFlowRequirements('link');
      expect(req.flow).toBe('link');
      expect(req.contractName).toBe('quickex');
      expect(req.minContractVersion).toBe(1);
      expect(req.schemaCompatibility).toEqual({ min: '1.0.0', max: '2.0.0' });
      expect(req.supportedWriteMethods).toContain('deposit');
    });

    it('returns defined flow requirements for quote flow', () => {
      const req = service.getFlowRequirements('quote');
      expect(req.flow).toBe('quote');
      expect(req.minContractVersion).toBe(1);
      expect(req.schemaCompatibility).toEqual({ min: '1.0.0', max: '2.0.0' });
    });

    it('returns defined flow requirements for pay_initiation flow', () => {
      const req = service.getFlowRequirements('pay_initiation');
      expect(req.flow).toBe('pay_initiation');
      expect(req.supportedWriteMethods).toEqual(
        expect.arrayContaining(['deposit', 'withdraw', 'refund']),
      );
    });
  });

  describe('getCompatibilityMetadata', () => {
    it('returns consistent compatibility metadata matching registry deployment', async () => {
      const metadata = await service.getCompatibilityMetadata('pay_initiation');
      expect(metadata).toMatchObject({
        contractName: 'quickex',
        network: 'testnet',
        contractId: 'CD2J6K7T3YJ77QXZP3ACTIVE',
        contractVersion: 2,
        schemaVersion: '1.2.0',
        schemaCompatibility: { min: '1.0.0', max: '2.0.0' },
        flow: 'pay_initiation',
        compatible: true,
        transition: { active: false },
      });
      expect(metadata.requirements).toBeDefined();
    });

    it('reports active transition when previousContractId is present within time window', async () => {
      const futureTime = new Date(Date.now() + 60_000).toISOString();
      mockRegistryReader.getRegistry.mockResolvedValueOnce({
        network: 'testnet',
        etag: 'w/"v2"',
        data: {
          quickex: {
            ...defaultDeployment,
            previousContractId: 'CD2J6K7T3YJ77QXZP3PREVIOUS',
            effectiveTime: futureTime,
          },
        },
      });

      const metadata = await service.getCompatibilityMetadata('link');
      expect(metadata.transition).toEqual({
        active: true,
        previousContractId: 'CD2J6K7T3YJ77QXZP3PREVIOUS',
        effectiveTime: futureTime,
        effectiveLedger: undefined,
      });
    });
  });

  describe('validateWriteCompatibility', () => {
    it('accepts valid assertions matching active contract deployment', async () => {
      const result = await service.validateWriteCompatibility({
        flow: 'pay_initiation',
        contractName: 'quickex',
        contractId: 'CD2J6K7T3YJ77QXZP3ACTIVE',
        contractVersion: 2,
        schemaVersion: '1.2.0',
      });
      expect(result.compatible).toBe(true);
      expect(result.contractId).toBe('CD2J6K7T3YJ77QXZP3ACTIVE');
    });

    it('rejects malformed schemaVersion with INVALID_CONTRACT_SCHEMA_VERSION', async () => {
      await expect(
        service.validateWriteCompatibility({
          flow: 'pay_initiation',
          schemaVersion: 'v1.0-beta',
        }),
      ).rejects.toThrow(BadRequestException);

      try {
        await service.validateWriteCompatibility({
          flow: 'pay_initiation',
          schemaVersion: '1.0',
        });
      } catch (err) {
        const res = (err as BadRequestException).getResponse() as Record<string, unknown>;
        expect(res.code).toBe(INVALID_CONTRACT_SCHEMA_VERSION_CODE);
      }
    });

    it('rejects unsupported schema version below minimum with CONTRACT_SCHEMA_INCOMPATIBLE', async () => {
      try {
        await service.validateWriteCompatibility({
          flow: 'pay_initiation',
          schemaVersion: '0.9.0',
        });
        fail('Should have thrown ConflictException');
      } catch (err) {
        expect(err).toBeInstanceOf(ConflictException);
        const res = (err as ConflictException).getResponse() as Record<string, unknown>;
        expect(res.code).toBe(CONTRACT_SCHEMA_INCOMPATIBLE_CODE);
        expect((res.details as Record<string, unknown>).reason).toBe('CLIENT_SCHEMA_TOO_OLD');
        expect((res.details as Record<string, unknown>).action).toBe('UPGRADE_CLIENT');
      }
    });

    it('rejects unsupported schema version above maximum with CONTRACT_SCHEMA_INCOMPATIBLE', async () => {
      try {
        await service.validateWriteCompatibility({
          flow: 'pay_initiation',
          schemaVersion: '3.0.0',
        });
        fail('Should have thrown ConflictException');
      } catch (err) {
        expect(err).toBeInstanceOf(ConflictException);
        const res = (err as ConflictException).getResponse() as Record<string, unknown>;
        expect(res.code).toBe(CONTRACT_SCHEMA_INCOMPATIBLE_CODE);
        expect((res.details as Record<string, unknown>).reason).toBe('CLIENT_SCHEMA_TOO_NEW');
        expect((res.details as Record<string, unknown>).action).toBe('REFRESH_CONTRACT_REGISTRY');
      }
    });

    it('rejects outdated contract version assertion with CONTRACT_VERSION_MISMATCH', async () => {
      try {
        await service.validateWriteCompatibility({
          flow: 'link',
          contractVersion: 1, // active is 2, and no transition grace configured
        });
        fail('Should have thrown ConflictException');
      } catch (err) {
        expect(err).toBeInstanceOf(ConflictException);
        const res = (err as ConflictException).getResponse() as Record<string, unknown>;
        expect(res.code).toBe(CONTRACT_VERSION_MISMATCH_CODE);
        expect((res.details as Record<string, unknown>).reason).toBe(
          'CLIENT_CONTRACT_VERSION_OUTDATED',
        );
      }
    });

    it('rejects mismatched contract ID with CONTRACT_DEPLOYMENT_OUTDATED', async () => {
      try {
        await service.validateWriteCompatibility({
          flow: 'pay_initiation',
          contractId: 'CD2J6K7T3YJ77QXZP3DIFFERENT',
        });
        fail('Should have thrown ConflictException');
      } catch (err) {
        expect(err).toBeInstanceOf(ConflictException);
        const res = (err as ConflictException).getResponse() as Record<string, unknown>;
        expect(res.code).toBe(CONTRACT_DEPLOYMENT_OUTDATED_CODE);
        expect((res.details as Record<string, unknown>).reason).toBe('CONTRACT_ID_MISMATCH');
        expect((res.details as Record<string, unknown>).action).toBe('REFRESH_CONTRACT_REGISTRY');
      }
    });

    describe('Upgrade rollout transitions', () => {
      it('allows previous contract deployment during active dual-read transition window', async () => {
        const futureTime = new Date(Date.now() + 120_000).toISOString();
        mockRegistryReader.getRegistry.mockResolvedValueOnce({
          network: 'testnet',
          etag: 'w/"v2"',
          data: {
            quickex: {
              ...defaultDeployment,
              version: 2,
              previousContractId: 'CD2J6K7T3YJ77QXZP3PREVIOUS',
              effectiveTime: futureTime,
              effectiveLedger: 50_000,
            },
          },
        });

        // Client still calls previous contract ID at version 1 (active is 2)
        const result = await service.validateWriteCompatibility(
          {
            flow: 'pay_initiation',
            contractId: 'CD2J6K7T3YJ77QXZP3PREVIOUS',
            contractVersion: 1,
            schemaVersion: '1.1.0',
          },
          49_000, // currentLedger < effectiveLedger
        );

        expect(result.compatible).toBe(true);
        expect(result.transition?.active).toBe(true);
      });

      it('rejects previous contract deployment once transition window has expired (by ledger)', async () => {
        mockRegistryReader.getRegistry.mockResolvedValueOnce({
          network: 'testnet',
          etag: 'w/"v2"',
          data: {
            quickex: {
              ...defaultDeployment,
              version: 2,
              previousContractId: 'CD2J6K7T3YJ77QXZP3PREVIOUS',
              effectiveLedger: 50_000,
            },
          },
        });

        try {
          await service.validateWriteCompatibility(
            {
              flow: 'pay_initiation',
              contractId: 'CD2J6K7T3YJ77QXZP3PREVIOUS',
            },
            50_001, // currentLedger >= effectiveLedger
          );
          fail('Should have thrown ConflictException');
        } catch (err) {
          expect(err).toBeInstanceOf(ConflictException);
          const res = (err as ConflictException).getResponse() as Record<string, unknown>;
          expect(res.code).toBe(CONTRACT_DEPLOYMENT_OUTDATED_CODE);
          expect((res.details as Record<string, unknown>).reason).toBe(
            'TRANSITION_WINDOW_EXPIRED',
          );
        }
      });

      it('rejects previous contract deployment once transition window has expired (by time)', async () => {
        const pastTime = new Date(Date.now() - 10_000).toISOString();
        mockRegistryReader.getRegistry.mockResolvedValueOnce({
          network: 'testnet',
          etag: 'w/"v2"',
          data: {
            quickex: {
              ...defaultDeployment,
              version: 2,
              previousContractId: 'CD2J6K7T3YJ77QXZP3PREVIOUS',
              effectiveTime: pastTime,
            },
          },
        });

        try {
          await service.validateWriteCompatibility({
            flow: 'pay_initiation',
            contractId: 'CD2J6K7T3YJ77QXZP3PREVIOUS',
          });
          fail('Should have thrown ConflictException');
        } catch (err) {
          expect(err).toBeInstanceOf(ConflictException);
          const res = (err as ConflictException).getResponse() as Record<string, unknown>;
          expect(res.code).toBe(CONTRACT_DEPLOYMENT_OUTDATED_CODE);
          expect((res.details as Record<string, unknown>).reason).toBe(
            'TRANSITION_WINDOW_EXPIRED',
          );
        }
      });

      it('supports rollback transition gracefully', async () => {
        // Rollback sets version back to 1 and previousContractId to v2's contract
        mockRegistryReader.getRegistry.mockResolvedValueOnce({
          network: 'testnet',
          etag: 'w/"v1-rolled-back"',
          data: {
            quickex: {
              id: 'CD2J6K7T3YJ77QXZP3ROLLED_BACK',
              version: 1,
              schemaVersion: '1.0.0',
              previousContractId: 'CD2J6K7T3YJ77QXZP3ACTIVE',
              schemaCompatibility: { min: '1.0.0', max: '2.0.0' },
            },
          },
        });

        const result = await service.validateWriteCompatibility({
          flow: 'quote',
          contractId: 'CD2J6K7T3YJ77QXZP3ROLLED_BACK',
          contractVersion: 1,
          schemaVersion: '1.0.0',
        });

        expect(result.compatible).toBe(true);
        expect(result.contractVersion).toBe(1);
      });
    });
  });

  describe('extractClientAssertionFromHeaders', () => {
    it('parses valid contract version, schema version, and contract ID from headers', () => {
      const assertion = service.extractClientAssertionFromHeaders({
        'x-contract-version': '3',
        'x-contract-schema-version': '1.5.0',
        'x-contract-id': 'CD2J6K7T3YJ77QXZP3EXAMPLE',
      });

      expect(assertion).toEqual({
        contractVersion: 3,
        schemaVersion: '1.5.0',
        contractId: 'CD2J6K7T3YJ77QXZP3EXAMPLE',
      });
    });

    it('rejects invalid X-Contract-Version header', () => {
      expect(() =>
        service.extractClientAssertionFromHeaders({
          'x-contract-version': 'abc',
        }),
      ).toThrow(BadRequestException);
    });

    it('returns empty object when no headers provided', () => {
      const assertion = service.extractClientAssertionFromHeaders({});
      expect(assertion).toEqual({});
    });
  });
});
