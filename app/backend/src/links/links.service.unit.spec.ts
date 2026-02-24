import { Test, TestingModule } from '@nestjs/testing';
import { LinksService } from './links.service';
import { LinkValidationError } from './errors';

describe('LinksService', () => {
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

  describe('generateMetadata', () => {
    it('should generate metadata for valid input', async () => {
      const result = await service.generateMetadata({
        amount: 50,
        memo: 'Payment for service',
        asset: 'XLM',
      });

      expect(result.amount).toBe('50.0000000');
      expect(result.memo).toBe('Payment for service');
      expect(result.asset).toBe('XLM');
      expect(result.memoType).toBe('text');
    });

    it('should throw error for negative amount', async () => {
      await expect(
        service.generateMetadata({ amount: -10 })
      ).rejects.toThrow(LinkValidationError);
    });

    it('should throw error for amount exceeding max', async () => {
      await expect(
        service.generateMetadata({ amount: 2000000 })
      ).rejects.toThrow(LinkValidationError);
    });

    it('should reject memo longer than 28 characters', async () => {
      await expect(
        service.generateMetadata({
          amount: 10,
          memo: 'This memo is way too long for Stellar',
        })
      ).rejects.toThrow(LinkValidationError);
    });

    it('should sanitize memo with special characters', async () => {
      const result = await service.generateMetadata({
        amount: 10,
        memo: '<script>alert("xss")</script>',
      });

      expect(result.memo).not.toContain('<');
      expect(result.memo).not.toContain('>');
    });

    it('should reject non-whitelisted asset', async () => {
      await expect(
        service.generateMetadata({
          amount: 10,
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          asset: 'SCAM' as any, // Intentionally invalid asset for testing
        })
      ).rejects.toThrow(LinkValidationError);
    });

    it('should trim whitespace from memo', async () => {
      const result = await service.generateMetadata({
        amount: 10,
        memo: '  Payment  ',
      });

      expect(result.memo).toBe('Payment');
    });

    it('should normalize amount to 7 decimals', async () => {
      const result = await service.generateMetadata({
        amount: 10.123456789,
      });

      expect(result.amount).toBe('10.1234568');
      expect(result.metadata.normalized).toBe(true);
    });

    it('should use default asset when not provided', async () => {
      const result = await service.generateMetadata({
        amount: 10,
      });

      expect(result.asset).toBe('XLM');
    });

    it('should generate canonical format correctly', async () => {
      const result = await service.generateMetadata({
        amount: 50,
        memo: 'Test payment',
        asset: 'USDC',
      });

      expect(result.canonical).toContain('amount=50.0000000');
      expect(result.canonical).toContain('asset=USDC');
      expect(result.canonical).toContain('memo=');
    });

    it('should handle empty string memo', async () => {
      const result = await service.generateMetadata({
        amount: 10,
        memo: '',
      });

      expect(result.memo).toBeNull();
    });

    it('should validate expiration days', async () => {
      await expect(
        service.generateMetadata({
          amount: 10,
          expirationDays: 500,
        })
      ).rejects.toThrow(LinkValidationError);
    });
  });
});
