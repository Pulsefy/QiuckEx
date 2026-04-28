import { Injectable, Logger, BadRequestException } from '@nestjs/common';
import { HorizonService } from '../transactions/horizon.service';
import {
  AggregatedStatsResponseDto,
  PeriodMetricDto,
  AssetMetricDto,
  PeriodComparisonDto,
  ComparisonResponseDto,
} from './dto/metrics-response.dto';
import {
  StatsQueryDto,
  TimeGrouping,
} from './dto/metrics-query.dto';
import { LRUCache } from 'lru-cache';

interface AggregatedTransaction {
  asset: string;
  amount: string;
  timestamp: string;
  status: 'Success' | 'Pending' | 'Failed';
  memo?: string;
}

@Injectable()
export class AnalyticsService {
  private readonly logger = new Logger(AnalyticsService.name);
  private readonly metricsCache: LRUCache<string, AggregatedStatsResponseDto>;

  constructor(private readonly horizonService: HorizonService) {
    this.metricsCache = new LRUCache({
      max: 100,
      ttl: 5 * 60 * 1000, // 5 minutes cache
    });
  }

  /**
   * Get aggregated statistics for a date range
   */
  async getAggregatedStats(
    accountId: string,
    query: StatsQueryDto,
  ): Promise<AggregatedStatsResponseDto> {
    const startTime = Date.now();

    // Validate date range
    this.validateDateRange(query.startDate, query.endDate);

    // Generate cache key
    const cacheKey = this.generateCacheKey(accountId, query);
    const cached = this.metricsCache.get(cacheKey);
    if (cached) {
      this.logger.debug(`Cache hit for account ${accountId}`);
      return cached;
    }

    try {
      // Fetch transactions from Horizon
      const transactions = await this.fetchTransactionsForDateRange(
        accountId,
        query.startDate,
        query.endDate,
        query.assets ? query.assets.split(',').map(a => a.trim()) : undefined,
      );

      // Aggregate by time period
      const timeSeries = this.aggregateByTimePeriod(
        transactions,
        query.startDate,
        query.endDate,
        query.grouping || TimeGrouping.DAILY,
        query.breakdownByAsset || false,
      );

      // Calculate summary
      const summary = this.calculateSummary(
        timeSeries,
        query.breakdownByAsset || false,
      );

      // Add comparison if requested
      if (query.includeComparison) {
        const previousPeriod = this.calculatePreviousPeriod(
          query.startDate,
          query.endDate,
          query.grouping || TimeGrouping.DAILY,
        );

        const previousTransactions = await this.fetchTransactionsForDateRange(
          accountId,
          previousPeriod.startDate,
          previousPeriod.endDate,
          query.assets ? query.assets.split(',').map(a => a.trim()) : undefined,
        );

        const previousTimeSeries = this.aggregateByTimePeriod(
          previousTransactions,
          previousPeriod.startDate,
          previousPeriod.endDate,
          query.grouping || TimeGrouping.DAILY,
          query.breakdownByAsset || false,
        );

        const previousSummary = this.calculateSummary(
          previousTimeSeries,
          query.breakdownByAsset || false,
        );

        summary.comparison = this.calculateComparison(summary, previousSummary);
      }

      const response: AggregatedStatsResponseDto = {
        summary,
        timeSeries,
        metadata: {
          requestedStartDate: query.startDate,
          requestedEndDate: query.endDate,
          granularity: query.grouping || TimeGrouping.DAILY,
          assetFilter: query.assets ? query.assets.split(',').map(a => a.trim()) : undefined,
          generatedAt: new Date().toISOString(),
          executionTimeMs: Date.now() - startTime,
        },
      };

      // Cache the result
      this.metricsCache.set(cacheKey, response);
      return response;
    } catch (error) {
      this.logger.error(`Error calculating aggregated stats: ${error}`);
      throw error;
    }
  }

  /**
   * Compare current period with previous period
   */
  async compareWithPreviousPeriod(
    accountId: string,
    query: StatsQueryDto,
  ): Promise<ComparisonResponseDto> {
    const startTime = Date.now();

    this.validateDateRange(query.startDate, query.endDate);

    // Get current period metrics
    const currentQuery = { ...query, includeComparison: false };
    const currentStats = await this.getAggregatedStats(accountId, currentQuery);
    const current = currentStats.summary;

    // Calculate previous period dates
    const previousPeriod = this.calculatePreviousPeriod(
      query.startDate,
      query.endDate,
      query.grouping || TimeGrouping.DAILY,
    );

    // Fetch and aggregate previous period
    const previousTransactions = await this.fetchTransactionsForDateRange(
      accountId,
      previousPeriod.startDate,
      previousPeriod.endDate,
      query.assets ? query.assets.split(',').map(a => a.trim()) : undefined,
    );

    const previousTimeSeries = this.aggregateByTimePeriod(
      previousTransactions,
      previousPeriod.startDate,
      previousPeriod.endDate,
      query.grouping || TimeGrouping.DAILY,
      query.breakdownByAsset || false,
    );

    const previous = this.calculateSummary(
      previousTimeSeries,
      query.breakdownByAsset || false,
    );

    const comparison = this.calculateComparison(current, previous);

    return {
      current,
      previous,
      comparison,
      metadata: {
        generatedAt: new Date().toISOString(),
        executionTimeMs: Date.now() - startTime,
      },
    };
  }

  /**
   * Fetch all transactions for a given date range
   * Note: Horizon API has pagination limits; this fetches in chunks
   */
  private async fetchTransactionsForDateRange(
    accountId: string,
    startDate: string,
    endDate: string,
    assetFilter?: string[],
  ): Promise<AggregatedTransaction[]> {
    const allTransactions: AggregatedTransaction[] = [];
    let cursor: string | undefined;
    const maxAttempts = 50; // Safety limit to prevent infinite loops
    let attempts = 0;

    try {
      while (attempts < maxAttempts) {
        attempts++;

        // Fetch batch of transactions
        const batch = await this.horizonService.getPayments(
          accountId,
          undefined,
          200, // Max supported by Horizon
          cursor,
        );

        if (!batch.items || batch.items.length === 0) {
          break;
        }

        // Filter by date range and assets
        const filtered = batch.items
          .filter(tx => {
            const txDate = new Date(tx.timestamp).getTime();
            const startTime = new Date(startDate).getTime();
            const endTime = new Date(endDate).getTime();
            return txDate >= startTime && txDate <= endTime;
          })
          .filter(tx => !assetFilter || assetFilter.includes(tx.asset))
          .map(tx => ({
            asset: tx.asset,
            amount: tx.amount,
            timestamp: tx.timestamp,
            status: (tx.status as 'Success' | 'Pending' | 'Failed') || 'Success',
            memo: tx.memo,
          }));

        allTransactions.push(...filtered);

        // Stop if we've gone past the end date
        if (batch.items.length > 0) {
          const oldestTxDate = new Date(
            batch.items[batch.items.length - 1].timestamp,
          ).getTime();
          if (oldestTxDate < new Date(startDate).getTime()) {
            break;
          }
        }

        // Continue pagination
        if (!batch.nextCursor) {
          break;
        }
        cursor = batch.nextCursor;
      }

      this.logger.debug(
        `Fetched ${allTransactions.length} transactions for account ${accountId}`,
      );
      return allTransactions;
    } catch (error) {
      this.logger.error(`Error fetching transactions: ${error}`);
      throw error;
    }
  }

  /**
   * Aggregate transactions by time period
   */
  private aggregateByTimePeriod(
    transactions: AggregatedTransaction[],
    startDate: string,
    endDate: string,
    grouping: TimeGrouping,
    breakdownByAsset: boolean,
  ): PeriodMetricDto[] {
    const periods = this.generatePeriods(startDate, endDate, grouping);
    const timeSeries: PeriodMetricDto[] = [];

    for (const period of periods) {
      const periodStart = new Date(period.startDate).getTime();
      const periodEnd = new Date(period.endDate).getTime();

      // Filter transactions for this period
      const periodTransactions = transactions.filter(tx => {
        const txTime = new Date(tx.timestamp).getTime();
        return txTime >= periodStart && txTime <= periodEnd;
      });

      // Calculate metrics
      const metrics = this.calculatePeriodMetrics(
        periodTransactions,
        breakdownByAsset,
      );
      metrics.period = period.startDate;

      timeSeries.push(metrics);
    }

    return timeSeries;
  }

  /**
   * Calculate metrics for a single period
   */
  private calculatePeriodMetrics(
    transactions: AggregatedTransaction[],
    breakdownByAsset: boolean,
  ): PeriodMetricDto {
    const successfulTx = transactions.filter(tx => tx.status === 'Success');
    const totalAmount = successfulTx.reduce(
      (sum, tx) => sum + parseFloat(tx.amount),
      0,
    );
    const successRate =
      transactions.length > 0
        ? (successfulTx.length / transactions.length) * 100
        : 0;

    // Extract unique links from memos (simplified - assumes memo format contains link identifier)
    const uniqueLinks = new Set(
      transactions.map(tx => tx.memo || 'unknown').filter(m => m !== 'unknown'),
    );
    const uniqueSuccessfulLinks = new Set(
      successfulTx.map(tx => tx.memo || 'unknown').filter(m => m !== 'unknown'),
    );

    const metrics: PeriodMetricDto = {
      period: new Date().toISOString(),
      totalVolume: totalAmount.toFixed(7),
      totalFees: '0.00000001', // Placeholder - would calculate based on transaction fees
      successRate: Math.round(successRate * 100) / 100,
      totalActiveLinks: uniqueLinks.size,
      totalPaidLinks: uniqueSuccessfulLinks.size,
      averageTransaction:
        successfulTx.length > 0
          ? (totalAmount / successfulTx.length).toFixed(7)
          : '0.0000000',
      transactionCount: transactions.length,
    };

    if (breakdownByAsset) {
      metrics.assetBreakdown = this.calculateAssetBreakdown(transactions);
    }

    return metrics;
  }

  /**
   * Calculate breakdown by asset
   */
  private calculateAssetBreakdown(
    transactions: AggregatedTransaction[],
  ): AssetMetricDto[] {
    const assetGroups = new Map<string, AggregatedTransaction[]>();

    for (const tx of transactions) {
      if (!assetGroups.has(tx.asset)) {
        assetGroups.set(tx.asset, []);
      }
      assetGroups.get(tx.asset)!.push(tx);
    }

    const breakdown: AssetMetricDto[] = [];
    for (const [asset, assetTxs] of assetGroups) {
      const successfulTx = assetTxs.filter(tx => tx.status === 'Success');
      const totalAmount = successfulTx.reduce(
        (sum, tx) => sum + parseFloat(tx.amount),
        0,
      );
      const successRate =
        assetTxs.length > 0 ? (successfulTx.length / assetTxs.length) * 100 : 0;

      const uniqueLinks = new Set(
        assetTxs.map(tx => tx.memo || 'unknown').filter(m => m !== 'unknown'),
      );
      const uniqueSuccessfulLinks = new Set(
        successfulTx.map(tx => tx.memo || 'unknown').filter(m => m !== 'unknown'),
      );

      breakdown.push({
        asset,
        volume: totalAmount.toFixed(7),
        fees: '0.00000001',
        successRate: Math.round(successRate * 100) / 100,
        activeLinks: uniqueLinks.size,
        paidLinks: uniqueSuccessfulLinks.size,
        averageTransaction:
          successfulTx.length > 0
            ? (totalAmount / successfulTx.length).toFixed(7)
            : '0.0000000',
        transactionCount: assetTxs.length,
      });
    }

    return breakdown;
  }

  /**
   * Calculate summary statistics from time-series data
   */
  private calculateSummary(
    timeSeries: PeriodMetricDto[],
    breakdownByAsset: boolean,
  ): PeriodMetricDto {
    if (timeSeries.length === 0) {
      return {
        period: new Date().toISOString(),
        totalVolume: '0.0000000',
        totalFees: '0.0000000',
        successRate: 0,
        totalActiveLinks: 0,
        totalPaidLinks: 0,
        averageTransaction: '0.0000000',
        transactionCount: 0,
      };
    }

    const allTransactionCounts = timeSeries.reduce(
      (sum, p) => sum + p.transactionCount,
      0,
    );
    const totalVolume = timeSeries.reduce(
      (sum, p) => sum + parseFloat(p.totalVolume),
      0,
    );
    const successRate =
      allTransactionCounts > 0
        ? timeSeries.reduce(
            (sum, p) => sum + p.successRate * p.transactionCount,
            0,
          ) / allTransactionCounts
        : 0;

    const summary: PeriodMetricDto = {
      period: timeSeries[0].period,
      totalVolume: totalVolume.toFixed(7),
      totalFees: '0.0000000',
      successRate: Math.round(successRate * 100) / 100,
      totalActiveLinks: timeSeries.reduce((sum, p) => sum + p.totalActiveLinks, 0),
      totalPaidLinks: timeSeries.reduce((sum, p) => sum + p.totalPaidLinks, 0),
      averageTransaction:
        timeSeries.length > 0
          ? (
              timeSeries.reduce(
                (sum, p) => sum + parseFloat(p.averageTransaction),
                0,
              ) / timeSeries.length
            ).toFixed(7)
          : '0.0000000',
      transactionCount: allTransactionCounts,
    };

    if (breakdownByAsset && timeSeries[0]?.assetBreakdown) {
      summary.assetBreakdown = this.aggregateAssetBreakdown(timeSeries);
    }

    return summary;
  }

  /**
   * Aggregate asset breakdowns from multiple time periods
   */
  private aggregateAssetBreakdown(
    timeSeries: PeriodMetricDto[],
  ): AssetMetricDto[] {
    const assetMap = new Map<string, AssetMetricDto>();

    for (const period of timeSeries) {
      if (!period.assetBreakdown) continue;

      for (const asset of period.assetBreakdown) {
        if (!assetMap.has(asset.asset)) {
          assetMap.set(asset.asset, {
            asset: asset.asset,
            volume: '0.0000000',
            fees: '0.0000000',
            successRate: 0,
            activeLinks: 0,
            paidLinks: 0,
            averageTransaction: '0.0000000',
            transactionCount: 0,
          });
        }

        const existing = assetMap.get(asset.asset)!;
        existing.volume = (
          parseFloat(existing.volume) + parseFloat(asset.volume)
        ).toFixed(7);
        existing.fees = (
          parseFloat(existing.fees) + parseFloat(asset.fees)
        ).toFixed(7);
        existing.successRate = asset.successRate;
        existing.activeLinks += asset.activeLinks;
        existing.paidLinks += asset.paidLinks;
        existing.transactionCount += asset.transactionCount;
      }
    }

    return Array.from(assetMap.values());
  }

  /**
   * Calculate comparison metrics
   */
  private calculateComparison(
    current: PeriodMetricDto,
    previous: PeriodMetricDto,
  ): PeriodComparisonDto {
    const currentVolume = parseFloat(current.totalVolume);
    const previousVolume = parseFloat(previous.totalVolume);
    const volumeChangePercent =
      previousVolume > 0
        ? ((currentVolume - previousVolume) / previousVolume) * 100
        : 0;

    const successRateChangePercent = current.successRate - previous.successRate;

    const activeLinksChangePercent =
      previous.totalActiveLinks > 0
        ? (
            (current.totalActiveLinks - previous.totalActiveLinks) /
            previous.totalActiveLinks
          ) * 100
        : 0;

    const paidLinksChangePercent =
      previous.totalPaidLinks > 0
        ? (
            (current.totalPaidLinks - previous.totalPaidLinks) /
            previous.totalPaidLinks
          ) * 100
        : 0;

    const currentAvgTx = parseFloat(current.averageTransaction);
    const previousAvgTx = parseFloat(previous.averageTransaction);
    const averageTransactionChangePercent =
      previousAvgTx > 0
        ? ((currentAvgTx - previousAvgTx) / previousAvgTx) * 100
        : 0;

    const transactionCountChange =
      current.transactionCount - previous.transactionCount;

    return {
      previousPeriod: previous.period,
      volumeChangePercent: Math.round(volumeChangePercent * 100) / 100,
      successRateChangePercent: Math.round(successRateChangePercent * 100) / 100,
      activeLinksChangePercent: Math.round(activeLinksChangePercent * 100) / 100,
      paidLinksChangePercent: Math.round(paidLinksChangePercent * 100) / 100,
      averageTransactionChangePercent:
        Math.round(averageTransactionChangePercent * 100) / 100,
      transactionCountChange,
    };
  }

  /**
   * Generate date periods based on grouping
   */
  private generatePeriods(
    startDate: string,
    endDate: string,
    grouping: TimeGrouping,
  ): Array<{ startDate: string; endDate: string }> {
    const periods: Array<{ startDate: string; endDate: string }> = [];
    let current = new Date(startDate);
    const end = new Date(endDate);

    while (current < end) {
      const periodStart = new Date(current);
      const periodEnd = new Date(current);

      if (grouping === TimeGrouping.DAILY) {
        periodEnd.setDate(periodEnd.getDate() + 1);
      } else if (grouping === TimeGrouping.WEEKLY) {
        periodEnd.setDate(periodEnd.getDate() + 7);
      } else if (grouping === TimeGrouping.MONTHLY) {
        periodEnd.setMonth(periodEnd.getMonth() + 1);
      }

      // Ensure period end doesn't exceed query end
      if (periodEnd > end) {
        periodEnd.setTime(end.getTime());
      }

      periods.push({
        startDate: periodStart.toISOString(),
        endDate: periodEnd.toISOString(),
      });

      current = periodEnd;
    }

    return periods;
  }

  /**
   * Calculate previous period dates
   */
  private calculatePreviousPeriod(
    startDate: string,
    endDate: string,
    grouping: TimeGrouping,
  ): { startDate: string; endDate: string } {
    const start = new Date(startDate);
    const end = new Date(endDate);

    const periodDuration = end.getTime() - start.getTime();
    const previousEnd = new Date(start.getTime() - 1);
    const previousStart = new Date(previousEnd.getTime() - periodDuration);

    return {
      startDate: previousStart.toISOString(),
      endDate: previousEnd.toISOString(),
    };
  }

  /**
   * Generate cache key for metrics query
   */
  private generateCacheKey(accountId: string, query: StatsQueryDto): string {
    return `${accountId}:${query.startDate}:${query.endDate}:${query.grouping}:${query.assets || 'all'}:${query.breakdownByAsset}:${query.includeComparison}`;
  }

  /**
   * Validate date range
   */
  private validateDateRange(startDate: string, endDate: string): void {
    const start = new Date(startDate);
    const end = new Date(endDate);

    if (isNaN(start.getTime()) || isNaN(end.getTime())) {
      throw new BadRequestException('Invalid date format. Use ISO 8601 format.');
    }

    if (start >= end) {
      throw new BadRequestException(
        'Start date must be before end date.',
      );
    }

    // Warn if range is more than 2 years
    const maxRange = 2 * 365 * 24 * 60 * 60 * 1000; // 2 years in ms
    if (end.getTime() - start.getTime() > maxRange) {
      this.logger.warn(
        'Large date range requested: ' +
          Math.round((end.getTime() - start.getTime()) / (365 * 24 * 60 * 60 * 1000)) +
          ' years',
      );
    }
  }
}
