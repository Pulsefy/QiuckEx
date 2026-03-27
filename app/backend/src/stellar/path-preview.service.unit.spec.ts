import { Test, TestingModule } from '@nestjs/testing';
import { BadRequestException, ServiceUnavailableException } from '@nestjs/common';
import { PathPreviewService } from './path-preview.service';
import { AppConfigService } from '../config/app-config.service';

const mockAppConfig = {
  isMainnet: false,
};

const BASE_URL = 'https://horizon-testnet.stellar.org';

describe('PathPreviewService', () => {
  let service: PathPreviewService;
  let fetchSpy: jest.SpyInstance;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        PathPreviewService,
        { provide: AppConfigService, useValue: mockAppConfig },
      ],
    }).compile();

    service = module.get<PathPreviewService>(PathPreviewService);
    fetchSpy = jest.spyOn(global, 'fetch');
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('previewPaths (strict-receive)', () => {
    it('should return paths from Horizon', async () => {
      const horizonResponse = {
        _embedded: {
          records: [
            {
              source_asset_type: 'native',
              source_amount: '100.0000000',
              destination_asset_type: 'credit_alphanum4',
              destination_asset_code: 'USDC',
              destination_asset_issuer:
                'GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN',
              destination_amount: '10.0000000',
              path: [],
            },
          ],
        },
      };

      fetchSpy.mockResolvedValueOnce({
        ok: true,
        json: async () => horizonResponse,
      } as Response);

      const result = await service.previewPaths({
        destinationAmount: '10',
        destinationAsset: {
          code: 'USDC',
          issuer: 'GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN',
        },
        sourceAssets: [{ code: 'XLM' }],
      });

      expect(result.horizonUrl).toBe(BASE_URL);
      expect(result.paths).toHaveLength(1);
      expect(result.paths[0].sourceAsset).toBe('XLM');
      expect(result.paths[0].destinationAmount).toBe('10.0000000');
    });

    it('should throw BadRequestException for unknown asset', async () => {
      await expect(
        service.previewPaths({
          destinationAmount: '10',
          destinationAsset: { code: 'UNKNOWN' },
          sourceAssets: [{ code: 'XLM' }],
        }),
      ).rejects.toThrow(BadRequestException);
    });

    it('should throw BadRequestException for mismatched issuer', async () => {
      await expect(
        service.previewPaths({
          destinationAmount: '10',
          destinationAsset: {
            code: 'USDC',
            issuer: 'GWRONGISSUER000000000000000000000000000000000000000000000',
          },
          sourceAssets: [{ code: 'XLM' }],
        }),
      ).rejects.toThrow(BadRequestException);
    });

    it('should throw ServiceUnavailableException when Horizon returns non-ok', async () => {
      fetchSpy.mockResolvedValueOnce({
        ok: false,
        status: 503,
        text: async () => 'Service Unavailable',
      } as Response);

      await expect(
        service.previewPaths({
          destinationAmount: '10',
          destinationAsset: {
            code: 'USDC',
            issuer: 'GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN',
          },
          sourceAssets: [{ code: 'XLM' }],
        }),
      ).rejects.toThrow(ServiceUnavailableException);
    });

    it('should return empty paths when Horizon returns no records', async () => {
      fetchSpy.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ _embedded: { records: [] } }),
      } as Response);

      const result = await service.previewPaths({
        destinationAmount: '10',
        destinationAsset: {
          code: 'USDC',
          issuer: 'GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN',
        },
        sourceAssets: [{ code: 'XLM' }],
      });

      expect(result.paths).toHaveLength(0);
    });

    it('should include path hops in results', async () => {
      const horizonResponse = {
        _embedded: {
          records: [
            {
              source_asset_type: 'native',
              source_amount: '50.0000000',
              destination_asset_type: 'credit_alphanum4',
              destination_asset_code: 'USDC',
              destination_asset_issuer:
                'GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN',
              destination_amount: '5.0000000',
              path: [
                {
                  asset_type: 'credit_alphanum4',
                  asset_code: 'AQUA',
                  asset_issuer:
                    'GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA',
                },
              ],
            },
          ],
        },
      };

      fetchSpy.mockResolvedValueOnce({
        ok: true,
        json: async () => horizonResponse,
      } as Response);

      const result = await service.previewPaths({
        destinationAmount: '5',
        destinationAsset: {
          code: 'USDC',
          issuer: 'GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN',
        },
        sourceAssets: [{ code: 'XLM' }],
      });

      expect(result.paths[0].hopCount).toBe(1);
      expect(result.paths[0].pathHops).toHaveLength(1);
    });
  });

  describe('strictSendPaths (strict-send)', () => {
    it('should return paths from Horizon strict-send endpoint', async () => {
      const horizonResponse = {
        _embedded: {
          records: [
            {
              source_asset_type: 'native',
              source_amount: '100.0000000',
              destination_asset_type: 'credit_alphanum4',
              destination_asset_code: 'USDC',
              destination_asset_issuer:
                'GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN',
              destination_amount: '10.0000000',
              path: [],
            },
          ],
        },
      };

      fetchSpy.mockResolvedValueOnce({
        ok: true,
        json: async () => horizonResponse,
      } as Response);

      const result = await service.strictSendPaths({
        sourceAmount: '100',
        sourceAsset: { code: 'XLM' },
        destinationAssets: [
          {
            code: 'USDC',
            issuer: 'GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN',
          },
        ],
      });

      expect(result.horizonUrl).toBe(BASE_URL);
      expect(result.paths).toHaveLength(1);
      expect(result.paths[0].sourceAmount).toBe('100.0000000');
      expect(result.paths[0].destinationAsset).toContain('USDC');
    });

    it('should call the strict-send Horizon endpoint', async () => {
      fetchSpy.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ _embedded: { records: [] } }),
      } as Response);

      await service.strictSendPaths({
        sourceAmount: '50',
        sourceAsset: { code: 'XLM' },
        destinationAssets: [
          {
            code: 'USDC',
            issuer: 'GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN',
          },
        ],
      });

      const calledUrl = (fetchSpy.mock.calls[0][0] as string);
      expect(calledUrl).toContain('/paths/strict-send');
      expect(calledUrl).toContain('source_asset_type=native');
    });

    it('should throw BadRequestException for unknown source asset', async () => {
      await expect(
        service.strictSendPaths({
          sourceAmount: '10',
          sourceAsset: { code: 'FAKE' },
          destinationAssets: [{ code: 'XLM' }],
        }),
      ).rejects.toThrow(BadRequestException);
    });

    it('should throw ServiceUnavailableException when Horizon is unreachable', async () => {
      fetchSpy.mockRejectedValueOnce(new Error('Network error'));

      await expect(
        service.strictSendPaths({
          sourceAmount: '10',
          sourceAsset: { code: 'XLM' },
          destinationAssets: [
            {
              code: 'USDC',
              issuer: 'GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN',
            },
          ],
        }),
      ).rejects.toThrow(ServiceUnavailableException);
    });

    it('should support multiple destination assets', async () => {
      fetchSpy.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ _embedded: { records: [] } }),
      } as Response);

      await service.strictSendPaths({
        sourceAmount: '10',
        sourceAsset: { code: 'XLM' },
        destinationAssets: [
          {
            code: 'USDC',
            issuer: 'GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN',
          },
          {
            code: 'AQUA',
            issuer: 'GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA',
          },
        ],
      });

      const calledUrl = (fetchSpy.mock.calls[0][0] as string);
      expect(calledUrl).toContain('destination_assets=');
    });

    it('should return empty paths when Horizon returns no records', async () => {
      fetchSpy.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ _embedded: { records: [] } }),
      } as Response);

      const result = await service.strictSendPaths({
        sourceAmount: '10',
        sourceAsset: { code: 'XLM' },
        destinationAssets: [
          {
            code: 'USDC',
            issuer: 'GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN',
          },
        ],
      });

      expect(result.paths).toHaveLength(0);
    });
  });
});
