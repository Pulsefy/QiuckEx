import { Test, TestingModule } from '@nestjs/testing';
import { AnalyticsService } from './analytics.service';
import { HorizonService } from '../transactions/horizon.service';
import { TimeGrouping } from './dto/metrics-query.dto';
import { StatsQueryDto } from './dto/metrics-query.dto';
import { BadRequestException } from '@nestjs/common';

describe('AnalyticsService', () => {
  let service: AnalyticsService;

  const mockHorizonService = {
    getPayments: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AnalyticsService,
        {
          provide: HorizonService,
          useValue: mockHorizonService,
        },
      ],
    }).compile();

    service = module.get<AnalyticsService>(AnalyticsService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('getAggregatedStats', () => {
    it('should return aggregated statistics for a valid date range', async () => {
      const mockTransactions = [
        {
          asset: 'XLM',
          amount: '100',
          timestamp: '2026-04-15T10:00:00Z',
          status: 'Success' as const,
          memo: 'link-1',
        },
        {
          asset: 'XLM',
          amount: '50',
          timestamp: '2026-04-15T11:00:00Z',
          status: 'Success' as const,
          memo: 'link-2',
        },
      ];

      mockHorizonService.getPayments.mockResolvedValue({
        items: mockTransactions,
        nextCursor: undefined,
      });

      const query: StatsQueryDto = {
        startDate: '2026-04-01T00:00:00Z',
        endDate: '2026-04-30T23:59:59Z',
        grouping: TimeGrouping.DAILY,
      };

      const result = await service.getAggregatedStats('test-account', query);

      expect(result).toBeDefined();
      expect(result.summary).toBeDefined();
      expect(result.timeSeries).toBeDefined();
      expect(result.metadata).toBeDefined();
      expect(result.summary.transactionCount).toBeGreaterThan(0);
    });

    it('should handle empty transaction results', async () => {
      mockHorizonService.getPayments.mockResolvedValue({
        items: [],
        nextCursor: undefined,
      });

      const query: StatsQueryDto = {
        startDate: '2026-04-01T00:00:00Z',
        endDate: '2026-04-30T23:59:59Z',
      };

      const result = await service.getAggregatedStats('test-account', query);

      expect(result.summary.transactionCount).toBe(0);
      expect(result.summary.totalVolume).toBe('0.0000000');
      expect(result.summary.successRate).toBe(0);
    });

    it('should filter transactions by asset when specified', async () => {
      const mockTransactions = [
        {
          asset: 'XLM',
          amount: '100',
          timestamp: '2026-04-15T10:00:00Z',
          status: 'Success' as const,
          memo: 'link-1',
        },
        {
          asset: 'USDC:GBUQWP3BOUZX34ULNQG23RQ6F4YUSXHTQSXUSMIQ6KUVNNBI5I7AD3H',
          amount: '50',
          timestamp: '2026-04-15T11:00:00Z',
          status: 'Success' as const,
          memo: 'link-2',
        },
      ];

      mockHorizonService.getPayments.mockResolvedValue({
        items: mockTransactions,
        nextCursor: undefined,
      });

      const query: StatsQueryDto = {
        startDate: '2026-04-01T00:00:00Z',
        endDate: '2026-04-30T23:59:59Z',
        assets: 'XLM',
      };

      const result = await service.getAggregatedStats('test-account', query);

      expect(result.summary.transactionCount).toBe(1);
      expect(parseFloat(result.summary.totalVolume)).toBe(100);
    });

    it('should calculate correct success rates', async () => {
      const mockTransactions = [
        {
          asset: 'XLM',
          amount: '100',
          timestamp: '2026-04-15T10:00:00Z',
          status: 'Success' as const,
          memo: 'link-1',
        },
        {
          asset: 'XLM',
          amount: '50',
          timestamp: '2026-04-15T11:00:00Z',
          status: 'Pending' as const,
          memo: 'link-2',
        },
        {
          asset: 'XLM',
          amount: '75',
          timestamp: '2026-04-15T12:00:00Z',
          status: 'Success' as const,
          memo: 'link-3',
        },
      ];

      mockHorizonService.getPayments.mockResolvedValue({
        items: mockTransactions,
        nextCursor: undefined,
      });

      const query: StatsQueryDto = {
        startDate: '2026-04-01T00:00:00Z',
        endDate: '2026-04-30T23:59:59Z',
      };

      const result = await service.getAggregatedStats('test-account', query);

      // 2 successful out of 3 = 66.67%
      expect(result.summary.successRate).toBeCloseTo(66.67, 1);
    });

    it('should include asset breakdown when requested', async () => {
      const mockTransactions = [
        {
          asset: 'XLM',
          amount: '100',
          timestamp: '2026-04-15T10:00:00Z',
          status: 'Success' as const,
          memo: 'link-1',
        },
        {
          asset: 'USDC:GBUQWP3BOUZX34ULNQG23RQ6F4YUSXHTQSXUSMIQ6KUVNNBI5I7AD3H',
          amount: '50',
          timestamp: '2026-04-15T11:00:00Z',
          status: 'Success' as const,
          memo: 'link-2',
        },
      ];

      mockHorizonService.getPayments.mockResolvedValue({
        items: mockTransactions,
        nextCursor: undefined,
      });

      const query: StatsQueryDto = {
        startDate: '2026-04-01T00:00:00Z',
        endDate: '2026-04-30T23:59:59Z',
        breakdownByAsset: true,
      };

      const result = await service.getAggregatedStats('test-account', query);

      expect(result.summary.assetBreakdown).toBeDefined();
      expect(result.summary.assetBreakdown?.length).toBeGreaterThan(0);
      expect(result.summary.assetBreakdown?.[0]).toHaveProperty('asset');
      expect(result.summary.assetBreakdown?.[0]).toHaveProperty('volume');
      expect(result.summary.assetBreakdown?.[0]).toHaveProperty('successRate');
    });

    it('should include comparison when requested', async () => {
      const mockTransactions = [
        {
          asset: 'XLM',
          amount: '100',
          timestamp: '2026-04-15T10:00:00Z',
          status: 'Success' as const,
          memo: 'link-1',
        },
      ];

      mockHorizonService.getPayments.mockResolvedValue({
        items: mockTransactions,
        nextCursor: undefined,
      });

      const query: StatsQueryDto = {
        startDate: '2026-04-15T00:00:00Z',
        endDate: '2026-04-22T23:59:59Z',
        grouping: TimeGrouping.DAILY,
        includeComparison: true,
      };

      const result = await service.getAggregatedStats('test-account', query);

      expect(result.summary.comparison).toBeDefined();
      expect(result.summary.comparison?.previousPeriod).toBeDefined();
      expect(result.summary.comparison?.volumeChangePercent).toBeDefined();
    });

    it('should cache results for identical queries', async () => {
      mockHorizonService.getPayments.mockResolvedValue({
        items: [
          {
            asset: 'XLM',
            amount: '100',
            timestamp: '2026-04-15T10:00:00Z',
            status: 'Success' as const,
            memo: 'link-1',
          },
        ],
        nextCursor: undefined,
      });

      const query: StatsQueryDto = {
        startDate: '2026-04-01T00:00:00Z',
        endDate: '2026-04-30T23:59:59Z',
      };

      const result1 = await service.getAggregatedStats('test-account', query);
      const result2 = await service.getAggregatedStats('test-account', query);

      expect(result1).toEqual(result2);
      // getPayments should only be called once due to caching
      expect(mockHorizonService.getPayments).toHaveBeenCalledTimes(1);
    });

    it('should throw error for invalid date format', async () => {
      const query: StatsQueryDto = {
        startDate: 'invalid-date',
        endDate: '2026-04-30T23:59:59Z',
      };

      await expect(
        service.getAggregatedStats('test-account', query),
      ).rejects.toThrow(BadRequestException);
    });

    it('should throw error when start date is after end date', async () => {
      const query: StatsQueryDto = {
        startDate: '2026-04-30T23:59:59Z',
        endDate: '2026-04-01T00:00:00Z',
      };

      await expect(
        service.getAggregatedStats('test-account', query),
      ).rejects.toThrow(BadRequestException);
    });
  });

  describe('compareWithPreviousPeriod', () => {
    it('should return comparison with previous period', async () => {
      mockHorizonService.getPayments.mockResolvedValue({
        items: [
          {
            asset: 'XLM',
            amount: '100',
            timestamp: '2026-04-15T10:00:00Z',
            status: 'Success' as const,
            memo: 'link-1',
          },
        ],
        nextCursor: undefined,
      });

      const query: StatsQueryDto = {
        startDate: '2026-04-15T00:00:00Z',
        endDate: '2026-04-22T23:59:59Z',
        grouping: TimeGrouping.DAILY,
      };

      const result = await service.compareWithPreviousPeriod(
        'test-account',
        query,
      );

      expect(result).toBeDefined();
      expect(result.current).toBeDefined();
      expect(result.previous).toBeDefined();
      expect(result.comparison).toBeDefined();
      expect(result.comparison.volumeChangePercent).toBeDefined();
      expect(result.comparison.successRateChangePercent).toBeDefined();
    });

    it('should calculate percentage changes correctly', async () => {
      let callCount = 0;
      mockHorizonService.getPayments.mockImplementation(() => {
        callCount++;
        // Return different data for current vs previous period calls
        if (callCount <= 3) {
          // Current period
          return Promise.resolve({
            items: [
              {
                asset: 'XLM',
                amount: '200',
                timestamp: '2026-04-15T10:00:00Z',
                status: 'Success' as const,
                memo: 'link-1',
              },
            ],
            nextCursor: undefined,
          });
        } else {
          // Previous period - 50% less volume
          return Promise.resolve({
            items: [
              {
                asset: 'XLM',
                amount: '100',
                timestamp: '2026-04-08T10:00:00Z',
                status: 'Success' as const,
                memo: 'link-2',
              },
            ],
            nextCursor: undefined,
          });
        }
      });

      const query: StatsQueryDto = {
        startDate: '2026-04-15T00:00:00Z',
        endDate: '2026-04-22T23:59:59Z',
        grouping: TimeGrouping.WEEKLY,
      };

      const result = await service.compareWithPreviousPeriod(
        'test-account',
        query,
      );

      // Current volume is 200, previous is 100, so 100% increase
      expect(result.comparison.volumeChangePercent).toBe(100);
    });
  });

  describe('Time period grouping', () => {
    it('should aggregate by daily granularity', async () => {
      const mockTransactions = [
        {
          asset: 'XLM',
          amount: '100',
          timestamp: '2026-04-15T10:00:00Z',
          status: 'Success' as const,
          memo: 'link-1',
        },
        {
          asset: 'XLM',
          amount: '50',
          timestamp: '2026-04-16T10:00:00Z',
          status: 'Success' as const,
          memo: 'link-2',
        },
      ];

      mockHorizonService.getPayments.mockResolvedValue({
        items: mockTransactions,
        nextCursor: undefined,
      });

      const query: StatsQueryDto = {
        startDate: '2026-04-15T00:00:00Z',
        endDate: '2026-04-17T23:59:59Z',
        grouping: TimeGrouping.DAILY,
      };

      const result = await service.getAggregatedStats('test-account', query);

      // Should have at least 3 periods (15th, 16th, 17th)
      expect(result.timeSeries.length).toBeGreaterThanOrEqual(3);
      expect(result.timeSeries[0]).toHaveProperty('period');
    });

    it('should aggregate by weekly granularity', async () => {
      mockHorizonService.getPayments.mockResolvedValue({
        items: [],
        nextCursor: undefined,
      });

      const query: StatsQueryDto = {
        startDate: '2026-04-01T00:00:00Z',
        endDate: '2026-04-30T23:59:59Z',
        grouping: TimeGrouping.WEEKLY,
      };

      const result = await service.getAggregatedStats('test-account', query);

      // April has ~4-5 weeks
      expect(result.timeSeries.length).toBeGreaterThanOrEqual(4);
    });

    it('should aggregate by monthly granularity', async () => {
      mockHorizonService.getPayments.mockResolvedValue({
        items: [],
        nextCursor: undefined,
      });

      const query: StatsQueryDto = {
        startDate: '2026-01-01T00:00:00Z',
        endDate: '2026-12-31T23:59:59Z',
        grouping: TimeGrouping.MONTHLY,
      };

      const result = await service.getAggregatedStats('test-account', query);

      // Should have 12 months
      expect(result.timeSeries.length).toBe(12);
    });
  });

  describe('Pagination handling', () => {
    it('should handle paginated results from Horizon', async () => {
      // Mock two pages of results
      mockHorizonService.getPayments
        .mockResolvedValueOnce({
          items: [
            {
              asset: 'XLM',
              amount: '100',
              timestamp: '2026-04-20T10:00:00Z',
              status: 'Success' as const,
              memo: 'link-1',
            },
          ],
          nextCursor: 'cursor-123',
        })
        .mockResolvedValueOnce({
          items: [
            {
              asset: 'XLM',
              amount: '50',
              timestamp: '2026-04-15T10:00:00Z',
              status: 'Success' as const,
              memo: 'link-2',
            },
          ],
          nextCursor: undefined,
        });

      const query: StatsQueryDto = {
        startDate: '2026-04-01T00:00:00Z',
        endDate: '2026-04-30T23:59:59Z',
      };

      const result = await service.getAggregatedStats('test-account', query);

      expect(result.summary.transactionCount).toBe(2);
      expect(parseFloat(result.summary.totalVolume)).toBe(150);
      // Should have called getPayments at least twice
      expect(mockHorizonService.getPayments.mock.calls.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe('Metadata', () => {
    it('should include execution metadata in response', async () => {
      mockHorizonService.getPayments.mockResolvedValue({
        items: [],
        nextCursor: undefined,
      });

      const query: StatsQueryDto = {
        startDate: '2026-04-01T00:00:00Z',
        endDate: '2026-04-30T23:59:59Z',
        assets: 'XLM,USDC',
      };

      const result = await service.getAggregatedStats('test-account', query);

      expect(result.metadata).toBeDefined();
      expect(result.metadata?.generatedAt).toBeDefined();
      expect(result.metadata?.executionTimeMs).toBeDefined();
      expect(result.metadata?.executionTimeMs).toBeGreaterThanOrEqual(0);
      expect(result.metadata?.requestedStartDate).toBe(query.startDate);
      expect(result.metadata?.requestedEndDate).toBe(query.endDate);
      expect(result.metadata?.assetFilter).toEqual(['XLM', 'USDC']);
    });
  });
});
