import { BadRequestException, Injectable } from '@nestjs/common';
import { SupabaseService } from '../supabase/supabase.service';
import {
  AnalyticsInterval,
  ReportType,
} from './dto/analytics-query.dto';

type PaymentRow = Record<string, unknown>;
type RpcSummaryRow = {
  total_transactions: number;
  successful_transactions: number;
  failed_transactions: number;
  conversion_rate: number;
  total_volume_usd: number;
  average_transaction_usd: number;
};
type RpcAssetRow = {
  asset: string;
  volume_usd: number;
  percentage: number;
  transaction_count: number;
};
type RpcTimeSeriesRow = {
  period: string;
  transaction_count: number;
  successful_transactions: number;
  volume_usd: number;
  volume_usdc: number;
  volume_xlm: number;
  asset_volumes?: Record<string, number> | null;
};

type NormalizedPayment = {
  createdAt: string;
  publicKeys: string[];
  asset: string;
  amount: number;
  amountUsd: number;
  status: string;
};

export type AnalyticsSummary = {
  totalTransactions: number;
  successfulTransactions: number;
  failedTransactions: number;
  conversionRate: number;
  totalVolumeUsd: number;
  averageTransactionUsd: number;
};

export type AssetDistributionItem = {
  asset: string;
  volumeUsd: number;
  percentage: number;
  transactionCount: number;
};

export type TimeSeriesItem = {
  period: string;
  transactionCount: number;
  successfulTransactions: number;
  volumeUsd: number;
  assetVolumes: Record<string, number>;
};

export type AnalyticsReport = {
  summary: AnalyticsSummary;
  assetDistribution: AssetDistributionItem[];
  timeSeries: TimeSeriesItem[];
  window: {
    startDate: string;
    endDate: string;
  };
};

@Injectable()
export class AnalyticsService {
  constructor(private readonly supabase: SupabaseService) {}

  async getAnalyticsReport(
    publicKey: string,
    startDate?: string,
    endDate?: string,
    interval: AnalyticsInterval = AnalyticsInterval.DAILY,
    organizationId?: string,
  ): Promise<AnalyticsReport> {
    const { startIso, endIso } = this.resolveDateWindow(startDate, endDate);

    const rpcReport = await this.fetchAggregatedReportViaRpc(
      publicKey,
      startIso,
      endIso,
      interval,
      organizationId,
    );
    if (rpcReport) {
      return rpcReport;
    }

    const rows = await this.fetchPaymentRows(
      publicKey,
      startIso,
      endIso,
      organizationId,
    );
    const payments = this.normalizeAndFilterRows(rows, publicKey);

    return {
      summary: this.buildSummary(payments),
      assetDistribution: this.buildAssetDistribution(payments),
      timeSeries: this.buildTimeSeries(payments, interval),
      window: {
        startDate: startIso,
        endDate: endIso,
      },
    };
  }

  async exportReport(
    publicKey: string,
    startDate: string | undefined,
    endDate: string | undefined,
    reportType: ReportType,
    interval: AnalyticsInterval,
    maxRows: number,
    organizationId?: string,
  ): Promise<{ report: AnalyticsReport; payments: NormalizedPayment[] }> {
    const { startIso, endIso } = this.resolveDateWindow(startDate, endDate);
    const rows = await this.fetchPaymentRows(
      publicKey,
      startIso,
      endIso,
      organizationId,
    );
    const payments = this.normalizeAndFilterRows(rows, publicKey).slice(
      0,
      Math.max(1, Math.min(maxRows || 500, 5000)),
    );

    const rpcReport = await this.fetchAggregatedReportViaRpc(
      publicKey,
      startIso,
      endIso,
      interval,
      organizationId,
    );
    const report: AnalyticsReport =
      rpcReport ??
      {
        summary: this.buildSummary(payments),
        assetDistribution: this.buildAssetDistribution(payments),
        timeSeries: this.buildTimeSeries(payments, interval),
        window: {
          startDate: startIso,
          endDate: endIso,
        },
      };

    if (reportType === ReportType.TAX) {
      report.summary.averageTransactionUsd = this.round2(
        report.summary.totalVolumeUsd / Math.max(report.summary.successfulTransactions, 1),
      );
    }

    return { report, payments };
  }

  buildCsvReport(
    report: AnalyticsReport,
    payments: NormalizedPayment[],
    reportType: ReportType,
  ): string {
    const lines: string[] = [];
    lines.push(`quickex_analytics_report_type,${reportType}`);
    lines.push(`start_date,${report.window.startDate}`);
    lines.push(`end_date,${report.window.endDate}`);
    lines.push('');
    lines.push('summary_metric,value');
    lines.push(`total_transactions,${report.summary.totalTransactions}`);
    lines.push(`successful_transactions,${report.summary.successfulTransactions}`);
    lines.push(`failed_transactions,${report.summary.failedTransactions}`);
    lines.push(`conversion_rate_percent,${report.summary.conversionRate}`);
    lines.push(`total_volume_usd,${report.summary.totalVolumeUsd}`);
    lines.push(`average_transaction_usd,${report.summary.averageTransactionUsd}`);
    lines.push('');
    lines.push('asset,volume_usd,percentage,transaction_count');
    report.assetDistribution.forEach((item) => {
      lines.push(
        [
          this.escapeCsv(item.asset),
          item.volumeUsd.toFixed(2),
          item.percentage.toFixed(2),
          item.transactionCount.toString(),
        ].join(','),
      );
    });
    lines.push('');
    lines.push('period,transaction_count,successful_transactions,volume_usd');
    report.timeSeries.forEach((item) => {
      lines.push(
        [
          this.escapeCsv(item.period),
          item.transactionCount.toString(),
          item.successfulTransactions.toString(),
          item.volumeUsd.toFixed(2),
        ].join(','),
      );
    });
    lines.push('');
    lines.push('created_at,asset,amount,amount_usd,status');
    payments.forEach((payment) => {
      lines.push(
        [
          this.escapeCsv(payment.createdAt),
          this.escapeCsv(payment.asset),
          payment.amount.toFixed(7),
          payment.amountUsd.toFixed(2),
          this.escapeCsv(payment.status),
        ].join(','),
      );
    });

    return lines.join('\n');
  }

  buildPdfReport(
    report: AnalyticsReport,
    payments: NormalizedPayment[],
    reportType: ReportType,
  ): Buffer {
    const lines: string[] = [
      `QuickEx ${reportType.toUpperCase()} Report`,
      `Date window: ${report.window.startDate} to ${report.window.endDate}`,
      `Total USD volume: ${report.summary.totalVolumeUsd.toFixed(2)}`,
      `Transactions: ${report.summary.totalTransactions}`,
      `Conversion rate: ${report.summary.conversionRate.toFixed(2)}%`,
      '',
      'Top assets by USD volume:',
      ...report.assetDistribution.slice(0, 5).map(
        (asset) =>
          `${asset.asset}: $${asset.volumeUsd.toFixed(2)} (${asset.percentage.toFixed(2)}%)`,
      ),
      '',
      'Recent transactions:',
      ...payments.slice(-10).map(
        (row) =>
          `${row.createdAt.slice(0, 19)} | ${row.asset} | $${row.amountUsd.toFixed(2)} | ${row.status}`,
      ),
    ];

    return this.createSimplePdf(lines);
  }

  private async fetchPaymentRows(
    publicKey: string,
    startIso: string,
    endIso: string,
    organizationId?: string,
  ): Promise<PaymentRow[]> {
    const client = this.supabase.getClient();

    let query = client
      .from('payment_records')
      .select('*')
      .or(`sender_public_key.eq.${publicKey},receiver_public_key.eq.${publicKey}`)
      .gte('created_at', startIso)
      .lte('created_at', endIso)
      .order('created_at', { ascending: true });

    if (organizationId) {
      query = query.eq('organization_id', organizationId);
    }

    const { data, error } = await query;

    if (error) {
      throw new BadRequestException({
        code: 'ANALYTICS_QUERY_FAILED',
        message: `Failed to fetch payment records: ${error.message}`,
      });
    }

    return (data ?? []) as PaymentRow[];
  }

  private async fetchAggregatedReportViaRpc(
    publicKey: string,
    startIso: string,
    endIso: string,
    interval: AnalyticsInterval,
    organizationId?: string,
  ): Promise<AnalyticsReport | null> {
    const client = this.supabase.getClient();
    const [summaryResult, assetsResult, timeSeriesResult] = await Promise.all([
      client.rpc('quickex_analytics_summary', {
        p_public_key: publicKey,
        p_start_date: startIso,
        p_end_date: endIso,
        p_organization_id: organizationId ?? null,
      }),
      client.rpc('quickex_analytics_asset_distribution', {
        p_public_key: publicKey,
        p_start_date: startIso,
        p_end_date: endIso,
        p_organization_id: organizationId ?? null,
      }),
      client.rpc('quickex_analytics_time_series', {
        p_public_key: publicKey,
        p_start_date: startIso,
        p_end_date: endIso,
        p_interval: interval,
        p_organization_id: organizationId ?? null,
      }),
    ]);

    if (summaryResult.error || assetsResult.error || timeSeriesResult.error) {
      return null;
    }

    const summaryRow = (summaryResult.data?.[0] ?? null) as RpcSummaryRow | null;
    if (!summaryRow) {
      return null;
    }

    const assetRows = (assetsResult.data ?? []) as RpcAssetRow[];
    const timeSeriesRows = (timeSeriesResult.data ?? []) as RpcTimeSeriesRow[];

    return {
      summary: {
        totalTransactions: Number(summaryRow.total_transactions ?? 0),
        successfulTransactions: Number(summaryRow.successful_transactions ?? 0),
        failedTransactions: Number(summaryRow.failed_transactions ?? 0),
        conversionRate: this.round2(Number(summaryRow.conversion_rate ?? 0)),
        totalVolumeUsd: this.round2(Number(summaryRow.total_volume_usd ?? 0)),
        averageTransactionUsd: this.round2(
          Number(summaryRow.average_transaction_usd ?? 0),
        ),
      },
      assetDistribution: assetRows
        .map((item) => ({
          asset: (item.asset ?? 'XLM').toUpperCase(),
          volumeUsd: this.round2(Number(item.volume_usd ?? 0)),
          percentage: this.round2(Number(item.percentage ?? 0)),
          transactionCount: Number(item.transaction_count ?? 0),
        }))
        .sort((a, b) => b.volumeUsd - a.volumeUsd),
      timeSeries: timeSeriesRows
        .map((item) => {
          const assetVolumes = item.asset_volumes ?? {
            USDC: Number(item.volume_usdc ?? 0),
            XLM: Number(item.volume_xlm ?? 0),
          };
          return {
            period: item.period,
            transactionCount: Number(item.transaction_count ?? 0),
            successfulTransactions: Number(item.successful_transactions ?? 0),
            volumeUsd: this.round2(Number(item.volume_usd ?? 0)),
            assetVolumes: Object.fromEntries(
              Object.entries(assetVolumes).map(([asset, volume]) => [
                asset.toUpperCase(),
                this.round2(Number(volume ?? 0)),
              ]),
            ),
          };
        })
        .sort((a, b) => a.period.localeCompare(b.period)),
      window: {
        startDate: startIso,
        endDate: endIso,
      },
    };
  }

  private normalizeAndFilterRows(
    rows: PaymentRow[],
    publicKey: string,
  ): NormalizedPayment[] {
    return rows
      .map((row) => this.normalizeRow(row))
      .filter((row): row is NormalizedPayment => row !== null)
      .filter((row) => row.publicKeys.includes(publicKey));
  }

  private normalizeRow(row: PaymentRow): NormalizedPayment | null {
    const createdAt = this.readString(row, ['created_at', 'createdAt']);
    if (!createdAt) {
      return null;
    }

    const amount = this.readNumber(row, ['amount']);
    const amountUsdRaw = this.readNumber(row, ['amount_usd', 'amountUsd']);
    const amountUsd = amountUsdRaw > 0 ? amountUsdRaw : amount;

    const asset = (
      this.readString(row, ['asset', 'asset_code', 'assetCode']) ?? 'XLM'
    ).toUpperCase();

    const status = (
      this.readString(row, ['status']) ?? 'unknown'
    ).toLowerCase();

    const publicKeys = [
      this.readString(row, ['sender_public_key', 'from_address', 'from']),
      this.readString(row, ['receiver_public_key', 'to_address', 'to']),
      this.readString(row, ['public_key', 'publicKey']),
    ].filter((item): item is string => Boolean(item));

    if (publicKeys.length === 0) {
      return null;
    }

    return {
      createdAt,
      publicKeys,
      asset,
      amount,
      amountUsd,
      status,
    };
  }

  private buildSummary(payments: NormalizedPayment[]): AnalyticsSummary {
    const totalTransactions = payments.length;
    const successfulTransactions = payments.filter((item) =>
      this.isSuccessfulStatus(item.status),
    ).length;
    const failedTransactions = payments.filter((item) =>
      this.isFailedStatus(item.status),
    ).length;
    const totalVolumeUsd = this.round2(
      payments.reduce((sum, item) => sum + item.amountUsd, 0),
    );
    const conversionRate = totalTransactions
      ? this.round2((successfulTransactions / totalTransactions) * 100)
      : 0;

    return {
      totalTransactions,
      successfulTransactions,
      failedTransactions,
      conversionRate,
      totalVolumeUsd,
      averageTransactionUsd: this.round2(
        totalVolumeUsd / Math.max(totalTransactions, 1),
      ),
    };
  }

  private buildAssetDistribution(
    payments: NormalizedPayment[],
  ): AssetDistributionItem[] {
    const map = new Map<string, { volume: number; count: number }>();
    const totalVolume = payments.reduce((sum, item) => sum + item.amountUsd, 0);

    payments.forEach((item) => {
      const current = map.get(item.asset) ?? { volume: 0, count: 0 };
      current.volume += item.amountUsd;
      current.count += 1;
      map.set(item.asset, current);
    });

    return Array.from(map.entries())
      .map(([asset, value]) => ({
        asset,
        volumeUsd: this.round2(value.volume),
        percentage: totalVolume > 0 ? this.round2((value.volume / totalVolume) * 100) : 0,
        transactionCount: value.count,
      }))
      .sort((a, b) => b.volumeUsd - a.volumeUsd);
  }

  private buildTimeSeries(
    payments: NormalizedPayment[],
    interval: AnalyticsInterval,
  ): TimeSeriesItem[] {
    const buckets = new Map<
      string,
      { count: number; successful: number; volume: number; assets: Record<string, number> }
    >();

    payments.forEach((item) => {
      const key = this.getBucketKey(item.createdAt, interval);
      const current = buckets.get(key) ?? {
        count: 0,
        successful: 0,
        volume: 0,
        assets: {},
      };
      current.count += 1;
      current.volume += item.amountUsd;
      current.assets[item.asset] = (current.assets[item.asset] ?? 0) + item.amountUsd;
      if (this.isSuccessfulStatus(item.status)) {
        current.successful += 1;
      }
      buckets.set(key, current);
    });

    return Array.from(buckets.entries())
      .map(([period, value]) => ({
        period,
        transactionCount: value.count,
        successfulTransactions: value.successful,
        volumeUsd: this.round2(value.volume),
        assetVolumes: Object.fromEntries(
          Object.entries(value.assets).map(([asset, volume]) => [
            asset,
            this.round2(volume),
          ]),
        ),
      }))
      .sort((a, b) => a.period.localeCompare(b.period));
  }

  private getBucketKey(createdAt: string, interval: AnalyticsInterval): string {
    const date = new Date(createdAt);
    if (Number.isNaN(date.getTime())) {
      return createdAt;
    }

    if (interval === AnalyticsInterval.MONTHLY) {
      return `${date.getUTCFullYear()}-${String(date.getUTCMonth() + 1).padStart(2, '0')}`;
    }

    if (interval === AnalyticsInterval.WEEKLY) {
      const weekStart = new Date(Date.UTC(
        date.getUTCFullYear(),
        date.getUTCMonth(),
        date.getUTCDate(),
      ));
      const day = weekStart.getUTCDay();
      const mondayShift = day === 0 ? -6 : 1 - day;
      weekStart.setUTCDate(weekStart.getUTCDate() + mondayShift);
      return `${weekStart.getUTCFullYear()}-W${String(this.getIsoWeek(weekStart)).padStart(2, '0')}`;
    }

    return `${date.getUTCFullYear()}-${String(date.getUTCMonth() + 1).padStart(2, '0')}-${String(
      date.getUTCDate(),
    ).padStart(2, '0')}`;
  }

  private getIsoWeek(date: Date): number {
    const utcDate = new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate()));
    const dayNum = utcDate.getUTCDay() || 7;
    utcDate.setUTCDate(utcDate.getUTCDate() + 4 - dayNum);
    const yearStart = new Date(Date.UTC(utcDate.getUTCFullYear(), 0, 1));
    return Math.ceil((((utcDate.getTime() - yearStart.getTime()) / 86400000) + 1) / 7);
  }

  private isSuccessfulStatus(status: string): boolean {
    return ['completed', 'paid', 'success', 'settled', 'confirmed'].includes(status);
  }

  private isFailedStatus(status: string): boolean {
    return ['failed', 'error', 'cancelled', 'rejected'].includes(status);
  }

  private readString(row: PaymentRow, keys: string[]): string | null {
    for (const key of keys) {
      const value = row[key];
      if (typeof value === 'string' && value.trim().length > 0) {
        return value.trim();
      }
    }
    return null;
  }

  private readNumber(row: PaymentRow, keys: string[]): number {
    for (const key of keys) {
      const value = row[key];
      if (typeof value === 'number' && Number.isFinite(value)) {
        return value;
      }
      if (typeof value === 'string' && value.trim() !== '') {
        const parsed = Number(value);
        if (Number.isFinite(parsed)) {
          return parsed;
        }
      }
    }
    return 0;
  }

  private resolveDateWindow(startDate?: string, endDate?: string): { startIso: string; endIso: string } {
    const end = endDate ? new Date(endDate) : new Date();
    const start = startDate
      ? new Date(startDate)
      : new Date(end.getTime() - 90 * 24 * 60 * 60 * 1000);

    if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime())) {
      throw new BadRequestException({
        code: 'INVALID_DATE_RANGE',
        message: 'startDate and endDate must be valid ISO-8601 strings',
      });
    }

    if (start > end) {
      throw new BadRequestException({
        code: 'INVALID_DATE_RANGE',
        message: 'startDate must be earlier than or equal to endDate',
      });
    }

    return {
      startIso: start.toISOString(),
      endIso: end.toISOString(),
    };
  }

  private escapeCsv(value: string): string {
    if (value.includes(',') || value.includes('"') || value.includes('\n')) {
      return `"${value.replace(/"/g, '""')}"`;
    }
    return value;
  }

  private createSimplePdf(lines: string[]): Buffer {
    const safeLines = lines.map((line) => this.escapePdfText(line));
    let content = 'BT\n/F1 11 Tf\n50 760 Td\n';
    safeLines.forEach((line, index) => {
      if (index > 0) {
        content += '0 -16 Td\n';
      }
      content += `(${line}) Tj\n`;
    });
    content += 'ET';

    const objects = [
      '<< /Type /Catalog /Pages 2 0 R >>',
      '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
      '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>',
      '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
      `<< /Length ${Buffer.byteLength(content, 'utf8')} >>\nstream\n${content}\nendstream`,
    ];

    let pdf = '%PDF-1.4\n';
    const offsets: number[] = [0];

    objects.forEach((obj, index) => {
      offsets[index + 1] = Buffer.byteLength(pdf, 'utf8');
      pdf += `${index + 1} 0 obj\n${obj}\nendobj\n`;
    });

    const xrefOffset = Buffer.byteLength(pdf, 'utf8');
    pdf += `xref\n0 ${objects.length + 1}\n`;
    pdf += '0000000000 65535 f \n';

    for (let i = 1; i <= objects.length; i += 1) {
      pdf += `${String(offsets[i]).padStart(10, '0')} 00000 n \n`;
    }

    pdf += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xrefOffset}\n%%EOF`;
    return Buffer.from(pdf, 'utf8');
  }

  private escapePdfText(value: string): string {
    return value.replace(/\\/g, '\\\\').replace(/\(/g, '\\(').replace(/\)/g, '\\)');
  }

  private round2(value: number): number {
    return Math.round(value * 100) / 100;
  }
}
