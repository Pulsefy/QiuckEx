import { Test, TestingModule } from '@nestjs/testing';
import { BulkPaymentLinksService } from './bulk-payment-links.service';
import { LinksService } from './links.service';
import { BulkPaymentLinkItemDto } from './dto/bulk-payment-link.dto';

describe('BulkPaymentLinksService', () => {
  let service: BulkPaymentLinksService;

  const mockLinksService = {
    generateMetadata: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        BulkPaymentLinksService,
        {
          provide: LinksService,
          useValue: mockLinksService,
        },
      ],
    }).compile();

    service = module.get<BulkPaymentLinksService>(BulkPaymentLinksService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('generateBulkLinks', () => {
    it('should generate multiple payment links successfully', async () => {
      const items: BulkPaymentLinkItemDto[] = [
        { amount: 100, asset: 'XLM', username: 'user1' },
        { amount: 200, asset: 'USDC', username: 'user2' },
      ];

      mockLinksService.generateMetadata.mockResolvedValue({
        amount: '100.0000000',
        asset: 'XLM',
        canonical: 'amount=100.0000000&asset=XLM&username=user1',
        username: 'user1',
      });

      const result = await service.generateBulkLinks(items);

      expect(result.success).toBe(true);
      expect(result.total).toBe(2);
      expect(result.links).toHaveLength(2);
      expect(result.processingTimeMs).toBeGreaterThanOrEqual(0);
    });

    it('should throw error for empty items array', async () => {
      await expect(service.generateBulkLinks([])).rejects.toThrow(
        'At least one payment link item is required',
      );
    });

    it('should throw error when exceeding max links limit', async () => {
      const items: BulkPaymentLinkItemDto[] = Array(501).fill({
        amount: 100,
        asset: 'XLM',
      });

      await expect(service.generateBulkLinks(items)).rejects.toThrow(
        'Maximum 500 links per request',
      );
    });

    it('should process links in batches', async () => {
      const items: BulkPaymentLinkItemDto[] = Array(100).fill({
        amount: 50,
        asset: 'XLM',
      });

      mockLinksService.generateMetadata.mockResolvedValue({
        amount: '50.0000000',
        asset: 'XLM',
        canonical: 'amount=50.0000000&asset=XLM',
      });

      const result = await service.generateBulkLinks(items);

      expect(result.success).toBe(true);
      expect(result.total).toBe(100);
      expect(mockLinksService.generateMetadata).toHaveBeenCalledTimes(100);
    });

    it('should handle partial failures and report errors', async () => {
      const items: BulkPaymentLinkItemDto[] = [
        { amount: 100, asset: 'XLM' },
        { amount: -1, asset: 'XLM' }, // This will fail validation
      ];

      mockLinksService.generateMetadata
        .mockResolvedValueOnce({
          amount: '100.0000000',
          asset: 'XLM',
          canonical: 'amount=100.0000000&asset=XLM',
        })
        .mockRejectedValueOnce(new Error('Invalid amount'));

      await expect(service.generateBulkLinks(items)).rejects.toThrow(
        'Failed to generate 1 link(s)',
      );
    });
  });

  describe('generateFromCSV', () => {
    it('should parse CSV and generate links', async () => {
      const csvContent = `amount,asset,username
100,XLM,user1
200,USDC,user2`;

      mockLinksService.generateMetadata.mockResolvedValue({
        amount: '100.0000000',
        asset: 'XLM',
        canonical: 'amount=100.0000000&asset=XLM&username=user1',
        username: 'user1',
      });

      const result = await service.generateFromCSV(csvContent);

      expect(result.success).toBe(true);
      expect(result.total).toBe(2);
    });

    it('should throw error for CSV without amount column', async () => {
      const csvContent = `asset,username
XLM,user1`;

      await expect(service.generateFromCSV(csvContent)).rejects.toThrow(
        'CSV must contain "amount" column',
      );
    });

    it('should throw error for empty CSV', async () => {
      const csvContent = '';

      await expect(service.generateFromCSV(csvContent)).rejects.toThrow(
        'No valid payment link items found in CSV',
      );
    });

    it('should handle CSV with quoted values', async () => {
      const csvContent = `amount,asset,memo
100,XLM,"Invoice #123"
200,USDC,"Payment for services"`;

      mockLinksService.generateMetadata.mockResolvedValue({
        amount: '100.0000000',
        asset: 'XLM',
        canonical: 'amount=100.0000000&asset=XLM',
        memo: 'Invoice #123',
      });

      const result = await service.generateFromCSV(csvContent);

      expect(result.success).toBe(true);
      expect(result.total).toBe(2);
    });

    it('should skip rows with invalid amounts', async () => {
      const csvContent = `amount,asset
100,XLM
invalid,USDC
200,XLM`;

      mockLinksService.generateMetadata.mockResolvedValue({
        amount: '100.0000000',
        asset: 'XLM',
        canonical: 'amount=100.0000000&asset=XLM',
      });

      const result = await service.generateFromCSV(csvContent);

      expect(result.success).toBe(true);
      expect(result.total).toBe(2); // Skips the invalid row
    });

    it('should parse acceptedAssets with pipe separator', async () => {
      const csvContent = `amount,asset,acceptedassets
100,XLM,XLM|USDC|AQUA`;

      mockLinksService.generateMetadata.mockResolvedValue({
        amount: '100.0000000',
        asset: 'XLM',
        canonical: 'amount=100.0000000&asset=XLM',
      });

      const result = await service.generateFromCSV(csvContent);

      expect(result.success).toBe(true);
      expect(result.total).toBe(1);
    });
  });
});
