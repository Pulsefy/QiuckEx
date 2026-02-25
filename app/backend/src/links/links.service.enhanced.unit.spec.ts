import { Test, TestingModule } from '@nestjs/testing';
import { LinksService } from './links.service';
import { LinkMetadataRequestDto } from '../dto';
import { LinkValidationError } from './errors';

describe('LinksService - Enhanced Features', () => {
  let service: LinksService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [LinksService],
    }).compile();

    service = module.get<LinksService>(LinksService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('Username validation', () => {
    it('should accept valid usernames', async () => {
      const request: LinkMetadataRequestDto = {
        amount: 100,
        username: 'john_doe123',
      };

      const result = await service.generateMetadata(request);
      expect(result.username).toBe('john_doe123');
    });

    it('should normalize usernames to lowercase', async () => {
      const request: LinkMetadataRequestDto = {
        amount: 100,
        username: 'John_Doe123',
      };

      const result = await service.generateMetadata(request);
      expect(result.username).toBe('john_doe123');
    });

    it('should reject usernames that are too short', async () => {
      const request: LinkMetadataRequestDto = {
        amount: 100,
        username: 'ab',
      };

      await expect(service.generateMetadata(request)).rejects.toThrow(LinkValidationError);
    });

    it('should reject usernames that are too long', async () => {
      const request: LinkMetadataRequestDto = {
        amount: 100,
        username: 'a'.repeat(33), // 33 characters
      };

      await expect(service.generateMetadata(request)).rejects.toThrow(LinkValidationError);
    });

    it('should reject reserved usernames', async () => {
      const request: LinkMetadataRequestDto = {
        amount: 100,
        username: 'admin',
      };

      await expect(service.generateMetadata(request)).rejects.toThrow(LinkValidationError);
    });

    it('should accept null/undefined usernames', async () => {
      const request: LinkMetadataRequestDto = {
        amount: 100,
        username: null,
      };

      const result = await service.generateMetadata(request);
      expect(result.username).toBeNull();
    });
  });

  describe('Destination validation', () => {
    it('should accept valid Stellar public keys', async () => {
      const validKey = 'GA3F2N3N4KVZ255TM74J5J7N3N4KVZ255TM74J5J7N3N4KVZ255TM74J';
      const request: LinkMetadataRequestDto = {
        amount: 100,
        destination: validKey,
      };

      const result = await service.generateMetadata(request);
      expect(result.destination).toBe(validKey);
    });

    it('should reject invalid Stellar public keys', async () => {
      const request: LinkMetadataRequestDto = {
        amount: 100,
        destination: 'INVALID_KEY',
      };

      await expect(service.generateMetadata(request)).rejects.toThrow(LinkValidationError);
    });

    it('should accept null/undefined destinations', async () => {
      const request: LinkMetadataRequestDto = {
        amount: 100,
        destination: null,
      };

      const result = await service.generateMetadata(request);
      expect(result.destination).toBeNull();
    });
  });

  describe('Reference ID validation', () => {
    it('should accept valid reference IDs', async () => {
      const request: LinkMetadataRequestDto = {
        amount: 100,
        referenceId: 'INV-12345',
      };

      const result = await service.generateMetadata(request);
      expect(result.referenceId).toBe('INV-12345');
    });

    it('should reject reference IDs that are too long', async () => {
      const request: LinkMetadataRequestDto = {
        amount: 100,
        referenceId: 'a'.repeat(65), // 65 characters
      };

      await expect(service.generateMetadata(request)).rejects.toThrow(LinkValidationError);
    });

    it('should accept null/undefined reference IDs', async () => {
      const request: LinkMetadataRequestDto = {
        amount: 100,
        referenceId: null,
      };

      const result = await service.generateMetadata(request);
      expect(result.referenceId).toBeNull();
    });
  });

  describe('Asset normalization', () => {
    it('should normalize asset symbols', async () => {
      const request: LinkMetadataRequestDto = {
        amount: 100,
        asset: 'XLM',
      };

      const result = await service.generateMetadata(request);
      expect(result.asset).toBe('XLM');
      expect(result.canonical).toContain('asset=XLM');
    });

    it('should handle USDC asset correctly', async () => {
      const request: LinkMetadataRequestDto = {
        amount: 100,
        asset: 'USDC',
      };

      const result = await service.generateMetadata(request);
      expect(result.asset).toBe('USDC');
      expect(result.metadata.assetType).toBe('credit_alphanum4');
      expect(result.metadata.assetIssuer).toBeDefined();
    });

    it('should handle XLM asset correctly', async () => {
      const request: LinkMetadataRequestDto = {
        amount: 100,
        asset: 'XLM',
      };

      const result = await service.generateMetadata(request);
      expect(result.asset).toBe('XLM');
      expect(result.metadata.assetType).toBe('native');
      expect(result.metadata.assetIssuer).toBeNull();
    });
  });

  describe('Additional metadata derivation', () => {
    it('should derive link type as standard for basic links', async () => {
      const request: LinkMetadataRequestDto = {
        amount: 100,
      };

      const result = await service.generateMetadata(request);
      expect(result.metadata.linkType).toBe('standard');
    });

    it('should derive link type as username for links with usernames', async () => {
      const request: LinkMetadataRequestDto = {
        amount: 100,
        username: 'john_doe',
      };

      const result = await service.generateMetadata(request);
      expect(result.metadata.linkType).toBe('username');
    });

    it('should derive link type as private for privacy-enabled links', async () => {
      const request: LinkMetadataRequestDto = {
        amount: 100,
        privacy: true,
      };

      const result = await service.generateMetadata(request);
      expect(result.metadata.linkType).toBe('private');
    });

    it('should calculate security level correctly', async () => {
      // Low security: basic link
      const basicRequest: LinkMetadataRequestDto = {
        amount: 100,
      };
      const basicResult = await service.generateMetadata(basicRequest);
      expect(basicResult.metadata.securityLevel).toBe('low');

      // Medium security: link with memo
      const mediumRequest: LinkMetadataRequestDto = {
        amount: 100,
        memo: 'test',
      };
      const mediumResult = await service.generateMetadata(mediumRequest);
      expect(mediumResult.metadata.securityLevel).toBe('medium');

      // High security: link with multiple security features
      const highRequest: LinkMetadataRequestDto = {
        amount: 100,
        memo: 'test',
        expirationDays: 30,
        privacy: true,
        destination: 'GA3F2N3N4KVZ255TM74J5J7N3N4KVZ255TM74J5J7N3N4KVZ255TM74J',
      };
      const highResult = await service.generateMetadata(highRequest);
      expect(highResult.metadata.securityLevel).toBe('high');
    });

    it('should handle expiration metadata', async () => {
      const request: LinkMetadataRequestDto = {
        amount: 100,
        expirationDays: 30,
      };

      const result = await service.generateMetadata(request);
      expect(result.metadata.isExpiring).toBe(true);
      expect(result.metadata.expiresInDays).toBe(30);
    });

    it('should handle non-expiring links', async () => {
      const request: LinkMetadataRequestDto = {
        amount: 100,
      };

      const result = await service.generateMetadata(request);
      expect(result.metadata.isExpiring).toBe(false);
      expect(result.metadata.expiresInDays).toBeUndefined();
    });
  });

  describe('Canonical format generation', () => {
    it('should generate proper canonical format with all parameters', async () => {
      const request: LinkMetadataRequestDto = {
        amount: 100.5,
        asset: 'USDC',
        memo: 'Payment for services',
        username: 'john_doe',
        destination: 'GA3F2N3N4KVZ255TM74J5J7N3N4KVZ255TM74J5J7N3N4KVZ255TM74J',
        referenceId: 'INV-12345',
      };

      const result = await service.generateMetadata(request);
      expect(result.canonical).toContain('amount=100.5000000');
      expect(result.canonical).toContain('asset=USDC');
      expect(result.canonical).toContain('memo=Payment+for+services');
      expect(result.canonical).toContain('username=john_doe');
      expect(result.canonical).toContain('destination=GA3F2N3N4KVZ255TM74J5J7N3N4KVZ255TM74J5J7N3N4KVZ255TM74J');
      expect(result.canonical).toContain('ref=INV-12345');
    });

    it('should generate canonical format with minimal parameters', async () => {
      const request: LinkMetadataRequestDto = {
        amount: 50,
      };

      const result = await service.generateMetadata(request);
      const params = new URLSearchParams(result.canonical);
      expect(params.get('amount')).toBe('50.0000000');
      expect(params.get('asset')).toBe('XLM');
      expect(params.has('memo')).toBe(false);
      expect(params.has('username')).toBe(false);
    });
  });

  describe('Edge cases and error handling', () => {
    it('should handle edge case with all optional fields null', async () => {
      const request: LinkMetadataRequestDto = {
        amount: 100,
        memo: null,
        asset: null,
        privacy: null,
        expirationDays: null,
        username: null,
        destination: null,
        referenceId: null,
      };

      const result = await service.generateMetadata(request);
      expect(result.amount).toBe('100.0000000');
      expect(result.memo).toBeNull();
      expect(result.asset).toBe('XLM');
      expect(result.privacy).toBe(false);
      expect(result.expiresAt).toBeNull();
      expect(result.username).toBeNull();
      expect(result.destination).toBeNull();
      expect(result.referenceId).toBeNull();
    });

    it('should maintain consistent error handling', async () => {
      const invalidRequest: LinkMetadataRequestDto = {
        amount: -10, // Invalid amount
      };

      await expect(service.generateMetadata(invalidRequest)).rejects.toThrow(LinkValidationError);
    });
  });
});