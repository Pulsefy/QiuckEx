# Analytics Module

Provides aggregated usage and financial metrics for the Developer Portal.

## Overview

The analytics module exposes time-series metrics on transaction volume, success rates, fees, and active payment links. All data is scoped to authenticated organizations and optimized for sub-500ms response times.

## Features

- **Time-series aggregation**: Daily, weekly, monthly groupings
- **Multiple metrics**: Volume, fees, success rates, active/paid links, average transaction
- **Asset breakdown**: Per-asset performance analytics
- **Period comparisons**: Track growth vs. previous periods
- **High performance**: LRU caching + materialized database views
- **Organization scoped**: Data automatically filtered by authenticated context

## Usage

### Quick Start

```bash
# Get April 2026 stats with daily granularity
curl -X GET "http://localhost:3000/analytics/stats?startDate=2026-04-01T00:00:00Z&endDate=2026-04-30T23:59:59Z" \
  -H "X-API-Key: your-api-key"
```

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/analytics/stats` | Aggregated statistics for date range |
| `GET` | `/analytics/stats/comparison` | Compare current vs. previous period |

See [../../docs/ANALYTICS-API.md](../../docs/ANALYTICS-API.md) for complete endpoint documentation.

## Architecture

### Service Layer (`analytics.service.ts`)

The `AnalyticsService` orchestrates metric aggregation:

1. **Fetch transactions**: Paginates through Horizon API results
2. **Filter & aggregate**: Groups by time period and asset
3. **Calculate metrics**: Computes volume, success rates, averages
4. **Apply caching**: LRU cache (5-minute TTL) prevents redundant calculations
5. **Build response**: Constructs typed response with metadata

```typescript
// Example service usage
const stats = await analyticsService.getAggregatedStats(
  'account-id',
  {
    startDate: '2026-04-01T00:00:00Z',
    endDate: '2026-04-30T23:59:59Z',
    grouping: TimeGrouping.DAILY,
    breakdownByAsset: true,
    includeComparison: true,
  }
);
```

### Controller Layer (`analytics.controller.ts`)

Express NestJS routes that:
- Validate query parameters via DTOs
- Extract organization context from API key
- Invoke service methods
- Return JSON responses

### Database Optimization (`supabase/migrations/20260428000001_create_analytics_views.sql`)

Materialized views pre-aggregate data:
- `daily_metrics`: Refreshed hourly
- `weekly_metrics`: Refreshed every 6 hours
- `monthly_metrics`: Refreshed every 12 hours

Indexes optimize queries on date + asset combinations.

## Testing

Run unit tests:

```bash
npm test -- src/analytics/analytics.service.spec.ts
```

Test coverage includes:
- Date range validation
- Aggregation by time period
- Asset filtering & breakdown
- Success rate calculations
- Period comparisons
- Caching behavior
- Error handling

## Performance

### Query Response Times

| Date Range | Typical Time |
|------------|--------------|
| 1 day | <50ms |
| 1 week | 50–100ms |
| 1 month | 100–200ms |
| 3 months | 200–400ms |
| 1 year | 400–800ms |

### Optimization Techniques

1. **LRU Cache**: 5-minute TTL on aggregation results
2. **Materialized Views**: Pre-computed daily/weekly/monthly aggregates
3. **Database Indexes**: On date, asset, organization, link ID
4. **Pagination**: Automatic Horizon API pagination (max 200 per request)
5. **Selective Filtering**: Asset and date filtering at query level

## Data Models

### Input DTOs

**MetricsQueryDto** (base):
```typescript
{
  startDate: string;           // ISO 8601
  endDate: string;             // ISO 8601
  grouping?: TimeGrouping;     // daily | weekly | monthly
  assets?: string;             // 'XLM,USDC:ISSUER'
  includeZeros?: boolean;      // false
}
```

**StatsQueryDto** (extends MetricsQueryDto):
```typescript
{
  ... MetricsQueryDto,
  breakdownByAsset?: boolean;  // false
  includeComparison?: boolean; // false
}
```

### Output DTOs

**PeriodMetricDto**:
```typescript
{
  period: string;
  totalVolume: string;
  totalFees: string;
  successRate: number;
  totalActiveLinks: number;
  totalPaidLinks: number;
  averageTransaction: string;
  transactionCount: number;
  assetBreakdown?: AssetMetricDto[];
  comparison?: PeriodComparisonDto;
}
```

**AggregatedStatsResponseDto**:
```typescript
{
  summary: PeriodMetricDto;
  timeSeries: PeriodMetricDto[];
  metadata?: {
    requestedStartDate: string;
    requestedEndDate: string;
    granularity: string;
    assetFilter?: string[];
    generatedAt: string;
    executionTimeMs: number;
  };
}
```

## Metrics Reference

| Metric | Formula | Notes |
|--------|---------|-------|
| **Volume** | Sum of successful transaction amounts | Asset units |
| **Fees** | Sum of network + platform fees | XLM |
| **Success Rate** | (successful / total) × 100 | Percentage |
| **Active Links** | Count of unique links with transactions | Includes all attempts |
| **Paid Links** | Count of unique links with successful tx | Subset of active |
| **Avg Transaction** | volume / successful_count | Single asset value |
| **Transaction Count** | Total attempts (all statuses) | Integer |

## Caching Strategy

The service uses an LRU cache with 5-minute TTL:

```typescript
private readonly metricsCache: LRUCache<string, AggregatedStatsResponseDto> = new LRUCache({
  max: 100,           // Max 100 cached queries
  ttl: 5 * 60 * 1000, // 5 minutes
});
```

**Cache Key**: `${accountId}:${startDate}:${endDate}:${grouping}:${assets}:${breakdownByAsset}:${includeComparison}`

**Invalidation**: TTL-based (5 minutes) or manual via admin endpoint

## Authentication

All endpoints require:
- **X-API-Key** header (for API clients), or
- **Bearer** token (for web dashboard)

See [../auth/guards/api-key.guard.ts](../auth/guards/api-key.guard.ts) for implementation.

## Error Handling

Common errors:

| Error | Status | Cause |
|-------|--------|-------|
| `INVALID_DATE_RANGE` | 400 | Start >= end date |
| `INVALID_DATE_FORMAT` | 400 | Not ISO 8601 |
| `INVALID_API_KEY` | 401 | Missing/expired key |
| `QUOTA_EXCEEDED` | 403 | Rate limit hit |
| `SERVICE_UNAVAILABLE` | 503 | Horizon API down |

## Development

### Adding New Metrics

1. Update `PeriodMetricDto` with new field
2. Implement calculation in `calculatePeriodMetrics()`
3. Update response examples in `ANALYTICS-API.md`
4. Add tests to `analytics.service.spec.ts`

### Changing Cache TTL

```typescript
// In analytics.service.ts, constructor
this.metricsCache = new LRUCache({
  max: 100,
  ttl: 10 * 60 * 1000, // Change to 10 minutes
});
```

### Testing Materialized Views

```sql
-- Refresh views manually (useful for testing)
SELECT refresh_analytics_views();

-- Query view directly
SELECT * FROM daily_metrics WHERE metric_date = CURRENT_DATE;
```

## Monitoring

Key metrics to monitor:

- **Cache hit rate**: Target >70% for repeated queries
- **P95 response time**: Target <500ms
- **Error rate**: Target <0.1%
- **Materialized view staleness**: Should be <1 hour

## See Also

- [ANALYTICS-API.md](../../docs/ANALYTICS-API.md) – Complete API reference
- [../../docs/ERROR-CODES.md](../../docs/ERROR-CODES.md) – Error code details
- [../transactions/horizon.service.ts](../transactions/horizon.service.ts) – Transaction data source
- [../auth/guards/api-key.guard.ts](../auth/guards/api-key.guard.ts) – Authentication
