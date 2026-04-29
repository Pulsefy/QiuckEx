import { Test, TestingModule } from '@nestjs/testing';
import { SupabaseService } from '../supabase/supabase.service';
import { AnalyticsInterval, ReportType } from './dto/analytics-query.dto';
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

  const mockClient = {
    from: jest.fn(() => queryBuilder),
    rpc: jest.fn(),
  };

  const mockSupabaseService = {
    getClient: jest.fn(() => mockClient),
  };

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
});
