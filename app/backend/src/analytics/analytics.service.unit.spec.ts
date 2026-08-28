import { Test, TestingModule } from '@nestjs/testing';
import { BadRequestException } from '@nestjs/common';
import { SupabaseService } from '../supabase/supabase.service';
import { AnalyticsInterval, ReportType } from './dto/analytics-query.dto';
import { TimeRange } from './dto/dashboard-summary.dto';
import { AnalyticsService } from './analytics.service';

describe('AnalyticsService', () => {
  let service: AnalyticsService;

  const sampleRows = [
    {
      created_at: '2026-04-01T10:00:00.000Z',
      sender_public_key: 'GA1234567890123456789012345678901234567890123456789012345',
      receiver_public_key: 'GB1234567890123456789012345678901234567890123456789012345',
      amount: '10',
      amount_usd: '10',
      asset: 'USDC',
      status: 'completed',
    },
    {
      created_at: '2026-04-02T10:00:00.000Z',
      sender_public_key: 'GB1234567890123456789012345678901234567890123456789012345',
      receiver_public_key: 'GC1234567890123456789012345678901234567890123456789012345',
      amount: '20',
      amount_usd: '20',
      asset_code: 'XLM',
      status: 'failed',
    },
    {
      created_at: '2026-04-03T10:00:00.000Z',
      from_address: 'GB1234567890123456789012345678901234567890123456789012345',
      to_address: 'GD1234567890123456789012345678901234567890123456789012345',
      amount: '25',
      amount_usd: '0',
      asset: 'USDC',
      status: 'paid',
    },
  ];

  const queryBuilder: {
    select: jest.Mock;
    or: jest.Mock;
    gte: jest.Mock;
    lte: jest.Mock;
    order: jest.Mock;
  } = {
    select: jest.fn(),
    or: jest.fn(),
    gte: jest.fn(),
    lte: jest.fn(),
    order: jest.fn(),
  };

  const mockClient: {
    from: jest.Mock;
    rpc: jest.Mock;
  } = {
    from: jest.fn(() => queryBuilder),
    rpc: jest.fn(),
  };

  const mockSupabaseService = {
    getClient: jest.fn(() => mockClient),
  };

  /**
   * The real service code never calls `.maybeSingle()` on these query
   * chains — it just `await`s the chain directly after the last filter
   * method (`.lte()`, `.eq()`, or `.in()`). A plain `mockReturnThis()`
   * chain is NOT awaitable to `{ data, error }` — it resolves immediately
   * to the mock object itself. So we make the returned mock a genuine
   * thenable: every chain method still returns `this` for chaining, but
   * the object itself resolves to `result` when awaited, regardless of
   * which method was called last.
   */
  function createSupabaseQueryMock(result: { data: unknown; error: unknown }) {
    const mock: Record<string, unknown> = {};
    const chainMethods = ['select', 'gte', 'lte', 'eq', 'or', 'in', 'order'];
    chainMethods.forEach((method) => {
      mock[method] = jest.fn(() => mock);
    });
    mock.maybeSingle = jest.fn().mockResolvedValue(result);
    mock.then = (
      resolve: (value: typeof result) => void,
      reject: (reason?: unknown) => void,
    ) => Promise.resolve(result).then(resolve, reject);
    return mock;
  }

  beforeEach(async () => {
    queryBuilder.select.mockReturnValue(queryBuilder);
    queryBuilder.or.mockReturnValue(queryBuilder);
    queryBuilder.gte.mockReturnValue(queryBuilder);
    queryBuilder.lte.mockReturnValue(queryBuilder);
    queryBuilder.order.mockResolvedValue({ data: sampleRows, error: null });
    mockClient.rpc.mockResolvedValue({
      data: null,
      error: { message: 'rpc not available' },
    });

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AnalyticsService,
        { provide: SupabaseService, useValue: mockSupabaseService },
      ],
    }).compile();

    service = module.get<AnalyticsService>(AnalyticsService);
    jest.clearAllMocks();
  });

  it('builds summary and asset distribution correctly', async () => {
    const report = await service.getAnalyticsReport(
      'GB1234567890123456789012345678901234567890123456789012345',
      '2026-04-01T00:00:00.000Z',
      '2026-04-29T23:59:59.999Z',
      AnalyticsInterval.DAILY,
    );

    expect(report.summary.totalTransactions).toBe(3);
    expect(report.summary.successfulTransactions).toBe(2);
    expect(report.summary.failedTransactions).toBe(1);
    expect(report.summary.totalVolumeUsd).toBe(55);
    expect(report.assetDistribution[0].asset).toBe('USDC');
    expect(report.assetDistribution[0].volumeUsd).toBe(35);
  });

  it('generates weekly time-series buckets', async () => {
    const report = await service.getAnalyticsReport(
      'GB1234567890123456789012345678901234567890123456789012345',
      '2026-04-01T00:00:00.000Z',
      '2026-04-29T23:59:59.999Z',
      AnalyticsInterval.WEEKLY,
    );

    expect(report.timeSeries.length).toBeGreaterThan(0);
    expect(report.timeSeries[0].period).toMatch(/^\d{4}-W\d{2}$/);
  });

  it('builds csv and pdf exports', async () => {
    const { report, payments } = await service.exportReport(
      'GB1234567890123456789012345678901234567890123456789012345',
      '2026-04-01T00:00:00.000Z',
      '2026-04-29T23:59:59.999Z',
      ReportType.ACCOUNTING,
      AnalyticsInterval.MONTHLY,
      200,
    );

    const csv = service.buildCsvReport(report, payments, ReportType.ACCOUNTING);
    const pdf = service.buildPdfReport(report, payments, ReportType.ACCOUNTING);

    expect(csv).toContain('summary_metric,value');
    expect(csv).toContain('created_at,asset,amount,amount_usd,status');
    expect(Buffer.isBuffer(pdf)).toBe(true);
    expect(pdf.toString('utf8')).toContain('%PDF-1.4');
  });

  it('uses SQL RPC aggregation when available', async () => {
    mockClient.rpc
      .mockResolvedValueOnce({
        data: [
          {
            total_transactions: 2,
            successful_transactions: 2,
            failed_transactions: 0,
            conversion_rate: 100,
            total_volume_usd: 300,
            average_transaction_usd: 150,
          },
        ],
        error: null,
      })
      .mockResolvedValueOnce({
        data: [
          {
            asset: 'USDC',
            volume_usd: 300,
            percentage: 100,
            transaction_count: 2,
          },
        ],
        error: null,
      })
      .mockResolvedValueOnce({
        data: [
          {
            period: '2026-04-01',
            transaction_count: 2,
            successful_transactions: 2,
            volume_usd: 300,
            volume_usdc: 300,
            volume_xlm: 0,
            asset_volumes: { USDC: 300 },
          },
        ],
        error: null,
      });

    const report = await service.getAnalyticsReport(
      'GB1234567890123456789012345678901234567890123456789012345',
      '2026-04-01T00:00:00.000Z',
      '2026-04-29T23:59:59.999Z',
      AnalyticsInterval.DAILY,
    );

    expect(report.summary.totalVolumeUsd).toBe(300);
    expect(report.assetDistribution[0].asset).toBe('USDC');
    expect(report.timeSeries[0].assetVolumes.USDC).toBe(300);
    expect(queryBuilder.select).not.toHaveBeenCalled();
  });

  it('should handle empty transaction results', async () => {
    queryBuilder.order.mockResolvedValueOnce({ data: [], error: null });

    const report = await service.getAnalyticsReport(
      'GB1234567890123456789012345678901234567890123456789012345',
      '2026-04-01T00:00:00.000Z',
      '2026-04-29T23:59:59.999Z',
    );

    expect(report.summary.totalTransactions).toBe(0);
    expect(report.summary.totalVolumeUsd).toBe(0);
  });

  it('should throw error for invalid date format', async () => {
    await expect(
      service.getAnalyticsReport(
        'GB1234567890123456789012345678901234567890123456789012345',
        'invalid-date',
        '2026-04-29T23:59:59.999Z',
      ),
    ).rejects.toThrow(BadRequestException);
  });

  it('should throw error when start date is after end date', async () => {
    await expect(
      service.getAnalyticsReport(
        'GB1234567890123456789012345678901234567890123456789012345',
        '2026-04-29T23:59:59.999Z',
        '2026-04-01T00:00:00.000Z',
      ),
    ).rejects.toThrow(BadRequestException);
  });

  describe('getDashboardSummary', () => {
    it('should return dashboard summary for populated account with week time range', async () => {
      mockClient.rpc
        .mockResolvedValueOnce({
          data: [
            {
              total_transactions: 10,
              successful_transactions: 8,
              failed_transactions: 2,
              conversion_rate: 80,
              total_volume_usd: 500,
              average_transaction_usd: 50,
            },
          ],
          error: null,
        })
        .mockResolvedValueOnce({
          data: [
            {
              asset: 'USDC',
              volume_usd: 300,
              percentage: 60,
              transaction_count: 6,
            },
            {
              asset: 'XLM',
              volume_usd: 200,
              percentage: 40,
              transaction_count: 4,
            },
          ],
          error: null,
        })
        .mockResolvedValueOnce({
          data: [
            {
              period: '2026-04-01',
              transaction_count: 5,
              successful_transactions: 4,
              volume_usd: 250,
              volume_usdc: 150,
              volume_xlm: 100,
              asset_volumes: { USDC: 150, XLM: 100 },
            },
          ],
          error: null,
        });

      mockClient.from.mockReturnValue(
        createSupabaseQueryMock({ data: [], error: null }),
      );

      const summary = await service.getDashboardSummary(
        'GB1234567890123456789012345678901234567890123456789012345',
        TimeRange.WEEK,
      );

      expect(summary.volume.totalVolumeUsd).toBe(500);
      expect(summary.volume.paymentCount).toBe(10);
      expect(summary.payments.successfulCount).toBe(8);
      expect(summary.payments.failedCount).toBe(2);
      expect(summary.payments.pendingCount).toBe(0);
      expect(summary.refunds.totalCount).toBe(0);
      expect(summary.refunds.pendingCount).toBe(0);
      expect(summary.refunds.approvedCount).toBe(0);
      expect(summary.health.successRate).toBe(80);
      expect(summary.health.deliveryFailureRate).toBe(0);
      expect(summary.window.startDate).toBeDefined();
      expect(summary.window.endDate).toBeDefined();
    });

    it('should return valid zero state for empty account', async () => {
      mockClient.rpc
        .mockResolvedValueOnce({
          data: [
            {
              total_transactions: 0,
              successful_transactions: 0,
              failed_transactions: 0,
              conversion_rate: 0,
              total_volume_usd: 0,
              average_transaction_usd: 0,
            },
          ],
          error: null,
        })
        .mockResolvedValueOnce({
          data: [],
          error: null,
        })
        .mockResolvedValueOnce({
          data: [],
          error: null,
        });

      mockClient.from.mockReturnValue(
        createSupabaseQueryMock({ data: [], error: null }),
      );

      const summary = await service.getDashboardSummary(
        'GB1234567890123456789012345678901234567890123456789012345',
        TimeRange.TODAY,
      );

      expect(summary.volume.totalVolumeUsd).toBe(0);
      expect(summary.volume.paymentCount).toBe(0);
      expect(summary.payments.successfulCount).toBe(0);
      expect(summary.payments.failedCount).toBe(0);
      expect(summary.payments.pendingCount).toBe(0);
      expect(summary.refunds.totalCount).toBe(0);
      expect(summary.refunds.pendingCount).toBe(0);
      expect(summary.refunds.approvedCount).toBe(0);
      expect(summary.health.successRate).toBe(0);
      expect(summary.health.deliveryFailureRate).toBe(0);
    });

    it('should handle custom time range with provided dates', async () => {
      mockClient.rpc
        .mockResolvedValueOnce({
          data: [
            {
              total_transactions: 5,
              successful_transactions: 5,
              failed_transactions: 0,
              conversion_rate: 100,
              total_volume_usd: 250,
              average_transaction_usd: 50,
            },
          ],
          error: null,
        })
        .mockResolvedValueOnce({
          data: [{ asset: 'USDC', volume_usd: 250, percentage: 100, transaction_count: 5 }],
          error: null,
        })
        .mockResolvedValueOnce({
          data: [
            {
              period: '2026-04-01',
              transaction_count: 5,
              successful_transactions: 5,
              volume_usd: 250,
              volume_usdc: 250,
              volume_xlm: 0,
              asset_volumes: { USDC: 250 },
            },
          ],
          error: null,
        });

      mockClient.from.mockReturnValue(
        createSupabaseQueryMock({ data: [], error: null }),
      );

      const summary = await service.getDashboardSummary(
        'GB1234567890123456789012345678901234567890123456789012345',
        TimeRange.CUSTOM,
        '2026-04-01T00:00:00.000Z',
        '2026-04-30T23:59:59.999Z',
      );

      expect(summary.volume.totalVolumeUsd).toBe(250);
      expect(summary.window.startDate).toBe('2026-04-01T00:00:00.000Z');
      expect(summary.window.endDate).toBe('2026-04-30T23:59:59.999Z');
    });

    it('should handle refund data correctly', async () => {
      mockClient.rpc
        .mockResolvedValueOnce({
          data: [
            {
              total_transactions: 10,
              successful_transactions: 8,
              failed_transactions: 2,
              conversion_rate: 80,
              total_volume_usd: 500,
              average_transaction_usd: 50,
            },
          ],
          error: null,
        })
        .mockResolvedValueOnce({
          data: [{ asset: 'USDC', volume_usd: 500, percentage: 100, transaction_count: 10 }],
          error: null,
        })
        .mockResolvedValueOnce({
          data: [
            {
              period: '2026-04-01',
              transaction_count: 10,
              successful_transactions: 8,
              volume_usd: 500,
              volume_usdc: 500,
              volume_xlm: 0,
              asset_volumes: { USDC: 500 },
            },
          ],
          error: null,
        });

      const refundData = [
        { status: 'pending' },
        { status: 'pending' },
        { status: 'approved' },
        { status: 'rejected' },
      ];

      // First `from()` call inside getDashboardSummary is fetchRefundCounts
      // ('refund_attempts'), so this is the payload that matters here.
      mockClient.from.mockReturnValue(
        createSupabaseQueryMock({ data: refundData, error: null }),
      );

      const summary = await service.getDashboardSummary(
        'GB1234567890123456789012345678901234567890123456789012345',
        TimeRange.WEEK,
      );

      expect(summary.refunds.totalCount).toBe(4);
      expect(summary.refunds.pendingCount).toBe(2);
      expect(summary.refunds.approvedCount).toBe(1);
    });

    it('should handle pending payments correctly', async () => {
      mockClient.rpc
        .mockResolvedValueOnce({
          data: [
            {
              total_transactions: 10,
              successful_transactions: 7,
              failed_transactions: 1,
              conversion_rate: 70,
              total_volume_usd: 500,
              average_transaction_usd: 50,
            },
          ],
          error: null,
        })
        .mockResolvedValueOnce({
          data: [{ asset: 'USDC', volume_usd: 500, percentage: 100, transaction_count: 10 }],
          error: null,
        })
        .mockResolvedValueOnce({
          data: [
            {
              period: '2026-04-01',
              transaction_count: 10,
              successful_transactions: 7,
              volume_usd: 500,
              volume_usdc: 500,
              volume_xlm: 0,
              asset_volumes: { USDC: 500 },
            },
          ],
          error: null,
        });

      // Inside getDashboardSummary, client.from() is called in this order:
      //   1) fetchRefundCounts        -> 'refund_attempts'
      //   2) fetchDeliveryFailureCount -> 'notification_logs'
      //      (both started inside the same Promise.all, in that order)
      //   3) fetchPendingPaymentCount -> 'payment_records'
      //      (called separately, after the Promise.all above resolves)
      // The 2-item payload needs to be on the THIRD call.
      mockClient.from
        .mockReturnValueOnce(createSupabaseQueryMock({ data: [], error: null })) // refund_attempts
        .mockReturnValueOnce(createSupabaseQueryMock({ data: [], error: null })) // notification_logs
        .mockReturnValue(
          createSupabaseQueryMock({
            data: [{ id: '1' }, { id: '2' }],
            error: null,
          }),
        ); // payment_records (pending)

      const summary = await service.getDashboardSummary(
        'GB1234567890123456789012345678901234567890123456789012345',
        TimeRange.WEEK,
      );

      expect(summary.payments.pendingCount).toBe(2);
    });
  });
});