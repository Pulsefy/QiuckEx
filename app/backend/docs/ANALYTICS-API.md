# Analytics API Documentation

## Overview

The Analytics API provides aggregated usage and financial metrics for the Developer Portal, offering insights into payment volume, success rates, active links, and asset breakdowns over specified time periods.

### Key Features

- **Time-series aggregation** for volume, fees, and success rates
- **Flexible granularity**: Daily, weekly, or monthly metrics
- **Asset breakdown** showing per-asset performance
- **Period comparisons** to track growth and trends
- **High performance**: Optimized queries respond within 500ms
- **Organization scoping**: Data automatically filtered to authenticated organization
- **Caching**: 5-minute cache on aggregations reduces database load

## Endpoints

### 1. Get Aggregated Statistics

**Endpoint**: `GET /analytics/stats`

**Description**: Returns time-series metrics for a specified date range, grouped by the requested granularity.

**Query Parameters**:

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `startDate` | ISO 8601 | Yes | - | Period start date (e.g., `2026-04-01T00:00:00Z`) |
| `endDate` | ISO 8601 | Yes | - | Period end date (e.g., `2026-04-30T23:59:59Z`) |
| `grouping` | string | No | `daily` | Time granularity: `daily`, `weekly`, or `monthly` |
| `assets` | string | No | - | Comma-separated asset codes to filter (e.g., `XLM,USDC`) |
| `breakdownByAsset` | boolean | No | `false` | Include per-asset breakdown in results |
| `includeComparison` | boolean | No | `false` | Include comparison with previous period |
| `includeZeros` | boolean | No | `false` | Include zero-value data points in time series |

**Response Format**:

```json
{
  "summary": {
    "period": "2026-04-01T00:00:00Z",
    "totalVolume": "5000.7500000",
    "totalFees": "0.0005000",
    "successRate": 92.3,
    "totalActiveLinks": 120,
    "totalPaidLinks": 108,
    "averageTransaction": "42.3100000",
    "transactionCount": 118,
    "assetBreakdown": [
      {
        "asset": "XLM",
        "volume": "3000.5000000",
        "fees": "0.0002500",
        "successRate": 94.2,
        "activeLinks": 75,
        "paidLinks": 68,
        "averageTransaction": "40.5400000",
        "transactionCount": 74
      },
      {
        "asset": "USDC:GBUQWP3BOUZX34ULNQG23RQ6F4YUSXHTQSXUSMIQ6KUVNNBI5I7AD3H",
        "volume": "2000.2500000",
        "fees": "0.0002500",
        "successRate": 89.5,
        "activeLinks": 45,
        "paidLinks": 40,
        "averageTransaction": "44.5000000",
        "transactionCount": 44
      }
    ],
    "comparison": {
      "previousPeriod": "2026-03-01T00:00:00Z",
      "volumeChangePercent": 15.2,
      "successRateChangePercent": 2.5,
      "activeLinksChangePercent": 8.3,
      "paidLinksChangePercent": 12.1,
      "averageTransactionChangePercent": -5.5,
      "transactionCountChange": 35
    }
  },
  "timeSeries": [
    {
      "period": "2026-04-01T00:00:00Z",
      "totalVolume": "150.5000000",
      "totalFees": "0.0001500",
      "successRate": 91.2,
      "totalActiveLinks": 12,
      "totalPaidLinks": 11,
      "averageTransaction": "13.6800000",
      "transactionCount": 11
    },
    {
      "period": "2026-04-02T00:00:00Z",
      "totalVolume": "200.2500000",
      "totalFees": "0.0002000",
      "successRate": 93.5,
      "totalActiveLinks": 15,
      "totalPaidLinks": 14,
      "averageTransaction": "14.3000000",
      "transactionCount": 14
    }
  ],
  "metadata": {
    "requestedStartDate": "2026-04-01T00:00:00Z",
    "requestedEndDate": "2026-04-30T23:59:59Z",
    "granularity": "daily",
    "assetFilter": ["XLM", "USDC:GBUQWP3BOUZX34ULNQG23RQ6F4YUSXHTQSXUSMIQ6KUVNNBI5I7AD3H"],
    "generatedAt": "2026-04-28T15:30:45.123Z",
    "executionTimeMs": 187
  }
}
```

**HTTP Status Codes**:

- `200 OK`: Successfully retrieved statistics
- `400 Bad Request`: Invalid date format, date range, or other validation error
- `401 Unauthorized`: Missing or invalid API key
- `429 Too Many Requests`: Rate limit exceeded
- `500 Internal Server Error`: Server error

**Example Requests**:

```bash
# Basic aggregated stats for April 2026 (daily granularity)
curl -X GET "http://localhost:3000/analytics/stats?startDate=2026-04-01T00:00:00Z&endDate=2026-04-30T23:59:59Z" \
  -H "X-API-Key: your-api-key"

# Weekly stats with asset breakdown
curl -X GET "http://localhost:3000/analytics/stats?startDate=2026-04-01T00:00:00Z&endDate=2026-04-30T23:59:59Z&grouping=weekly&breakdownByAsset=true" \
  -H "X-API-Key: your-api-key"

# XLM only with comparison to previous period
curl -X GET "http://localhost:3000/analytics/stats?startDate=2026-04-01T00:00:00Z&endDate=2026-04-30T23:59:59Z&assets=XLM&includeComparison=true" \
  -H "X-API-Key: your-api-key"

# Monthly stats for full year with breakdowns
curl -X GET "http://localhost:3000/analytics/stats?startDate=2026-01-01T00:00:00Z&endDate=2026-12-31T23:59:59Z&grouping=monthly&breakdownByAsset=true" \
  -H "X-API-Key: your-api-key"
```

---

### 2. Compare Periods

**Endpoint**: `GET /analytics/stats/comparison`

**Description**: Returns side-by-side comparison of current period with the equivalent previous period, showing percentage changes for all metrics.

**Query Parameters**: Same as `/analytics/stats` (minus `includeComparison` flag)

**Response Format**:

```json
{
  "current": {
    "period": "2026-04-15T00:00:00Z",
    "totalVolume": "3500.0000000",
    "totalFees": "0.0003500",
    "successRate": 94.5,
    "totalActiveLinks": 85,
    "totalPaidLinks": 78,
    "averageTransaction": "44.8700000",
    "transactionCount": 78,
    "assetBreakdown": [
      {
        "asset": "XLM",
        "volume": "2400.0000000",
        "fees": "0.0002400",
        "successRate": 95.8,
        "activeLinks": 55,
        "paidLinks": 52,
        "averageTransaction": "46.1500000",
        "transactionCount": 52
      },
      {
        "asset": "USDC:GBUQWP3BOUZX34ULNQG23RQ6F4YUSXHTQSXUSMIQ6KUVNNBI5I7AD3H",
        "volume": "1100.0000000",
        "fees": "0.0001100",
        "successRate": 91.7,
        "activeLinks": 30,
        "paidLinks": 26,
        "averageTransaction": "42.3000000",
        "transactionCount": 26
      }
    ]
  },
  "previous": {
    "period": "2026-04-08T00:00:00Z",
    "totalVolume": "3000.0000000",
    "totalFees": "0.0003000",
    "successRate": 91.2,
    "totalActiveLinks": 78,
    "totalPaidLinks": 71,
    "averageTransaction": "42.2500000",
    "transactionCount": 71,
    "assetBreakdown": []
  },
  "comparison": {
    "previousPeriod": "2026-04-08T00:00:00Z",
    "volumeChangePercent": 16.67,
    "successRateChangePercent": 3.3,
    "activeLinksChangePercent": 8.97,
    "paidLinksChangePercent": 9.86,
    "averageTransactionChangePercent": 6.13,
    "transactionCountChange": 7
  },
  "metadata": {
    "generatedAt": "2026-04-28T15:30:45.123Z",
    "executionTimeMs": 234
  }
}
```

**Example Requests**:

```bash
# Compare current week vs previous week
curl -X GET "http://localhost:3000/analytics/stats/comparison?startDate=2026-04-22T00:00:00Z&endDate=2026-04-28T23:59:59Z&grouping=weekly" \
  -H "X-API-Key: your-api-key"

# Compare current month vs previous month
curl -X GET "http://localhost:3000/analytics/stats/comparison?startDate=2026-04-01T00:00:00Z&endDate=2026-04-30T23:59:59Z&grouping=monthly&breakdownByAsset=true" \
  -H "X-API-Key: your-api-key"
```

---

## Metrics Reference

### Volume (`totalVolume` / `volume`)
- **Definition**: Sum of all transaction amounts in the period
- **Unit**: Asset units (e.g., XLM, USDC)
- **Notes**: Only counts successful transactions

### Fees (`totalFees` / `fees`)
- **Definition**: Total transaction fees paid
- **Unit**: XLM (Stellar's native asset)
- **Notes**: Includes Horizon API fees and network fees

### Success Rate (`successRate`)
- **Definition**: Percentage of transactions that completed successfully
- **Formula**: `(successful_transactions / total_transactions) * 100`
- **Range**: 0–100%
- **Notes**: "Success" = transaction confirmed on Stellar ledger; "Pending" = awaiting confirmation; "Failed" = rejected by network

### Active Links (`totalActiveLinks` / `activeLinks`)
- **Definition**: Number of unique payment links used in the period
- **Unit**: Integer count
- **Notes**: A link is "active" if it has at least one transaction attempt

### Paid Links (`totalPaidLinks` / `paidLinks`)
- **Definition**: Number of unique payment links that received at least one successful transaction
- **Unit**: Integer count
- **Notes**: Subset of active links

### Average Transaction (`averageTransaction`)
- **Definition**: Mean transaction amount across all successful transactions
- **Formula**: `total_volume / successful_transaction_count`
- **Unit**: Asset units
- **Notes**: Excludes pending/failed transactions

### Transaction Count (`transactionCount`)
- **Definition**: Total number of transactions in the period
- **Unit**: Integer count
- **Notes**: Includes successful, pending, and failed transactions

---

## Authentication

All endpoints require either:

1. **API Key** (X-API-Key header)
   ```bash
   curl -H "X-API-Key: your-api-key-here" ...
   ```

2. **Bearer Token** (Authorization header)
   ```bash
   curl -H "Authorization: Bearer your-jwt-token" ...
   ```

### Rate Limits

- **Unauthenticated**: 10 requests/minute
- **With API Key**: 100 requests/minute (varies by plan)
- **Rate limit info**: Check response headers `X-RateLimit-Remaining` and `X-RateLimit-Reset`

---

## Performance Considerations

### Query Optimization

1. **Cache Strategy**: Results are cached for 5 minutes
   - Same query parameters = cache hit
   - Cache bust: include `nocache=true` parameter (admin only)

2. **Optimal Date Ranges**:
   - **Single day** to **1 month**: <100ms
   - **1–3 months**: 100–200ms
   - **3–12 months**: 200–500ms
   - **>1 year**: 500ms–2s (consider filtering by asset)

3. **Pagination Limits**:
   - Horizon API (data source) limits to 200 records per page
   - Large date ranges paginate automatically
   - Max concurrent pagination attempts: 50

4. **Asset Filtering**:
   - Filtering by asset reduces payload and processing time
   - Example: `assets=XLM` vs `assets=USDC:GBUQWP3...`

### Materialized Views

- **Daily metrics**: Refreshed hourly
- **Weekly metrics**: Refreshed every 6 hours
- **Monthly metrics**: Refreshed every 12 hours
- **Manual refresh**: `POST /admin/analytics/refresh` (admin only)

---

## Data Accuracy

### Important Notes

1. **Transaction Data Source**: Stellar Horizon API
   - Data reflects only finalized transactions
   - Pending transactions may take 30–60 seconds to appear
   - Failed transactions are included in counts but excluded from volume

2. **Time Zones**: All dates MUST be in UTC (ISO 8601 format)
   - `2026-04-28T15:30:00Z` ✅ (UTC)
   - `2026-04-28T15:30:00-04:00` ✅ (with offset)
   - `2026-04-28 15:30:00` ❌ (missing Z or offset)

3. **Asset Codes**:
   - Native asset: `XLM`
   - Non-native: `CODE:ISSUER_ACCOUNT_ID`
   - Example: `USDC:GBUQWP3BOUZX34ULNQG23RQ6F4YUSXHTQSXUSMIQ6KUVNNBI5I7AD3H`

4. **Historical Data**: Available back to platform launch (January 2026)

---

## Error Handling

### Common Error Responses

**400 Bad Request**:
```json
{
  "error": "INVALID_DATE_RANGE",
  "message": "Start date must be before end date.",
  "statusCode": 400
}
```

**401 Unauthorized**:
```json
{
  "error": "INVALID_API_KEY",
  "message": "API key is invalid or expired.",
  "statusCode": 401
}
```

**429 Too Many Requests**:
```json
{
  "error": "RATE_LIMIT_EXCEEDED",
  "message": "You have exceeded your rate limit. Retry after 60 seconds.",
  "statusCode": 429,
  "retryAfter": 60
}
```

### Retry Strategy

- **4xx errors**: Do not retry (validation or auth errors)
- **5xx errors**: Retry with exponential backoff (1s, 2s, 4s, 8s max)
- **429 errors**: Retry after the `Retry-After` header value

---

## Examples

### JavaScript/TypeScript

```typescript
import axios from 'axios';

const apiKey = 'your-api-key-here';
const baseUrl = 'http://localhost:3000';

// Fetch April 2026 stats (daily granularity)
async function getMonthlyStats() {
  try {
    const response = await axios.get(`${baseUrl}/analytics/stats`, {
      params: {
        startDate: '2026-04-01T00:00:00Z',
        endDate: '2026-04-30T23:59:59Z',
        grouping: 'daily',
        breakdownByAsset: true,
      },
      headers: { 'X-API-Key': apiKey },
    });

    console.log('Summary:', response.data.summary);
    console.log('Time Series:', response.data.timeSeries);
    console.log('Execution Time:', response.data.metadata.executionTimeMs, 'ms');
  } catch (error) {
    console.error('Error:', error.response?.data || error.message);
  }
}

// Compare current week with previous week
async function compareWeeks() {
  const startDate = new Date();
  startDate.setDate(startDate.getDate() - 7);
  
  const endDate = new Date();

  try {
    const response = await axios.get(`${baseUrl}/analytics/stats/comparison`, {
      params: {
        startDate: startDate.toISOString(),
        endDate: endDate.toISOString(),
        grouping: 'weekly',
      },
      headers: { 'X-API-Key': apiKey },
    });

    console.log(`Volume change: ${response.data.comparison.volumeChangePercent}%`);
    console.log(`Success rate change: ${response.data.comparison.successRateChangePercent}%`);
  } catch (error) {
    console.error('Error:', error.response?.data || error.message);
  }
}

getMonthlyStats();
compareWeeks();
```

### Python

```python
import requests
from datetime import datetime, timedelta

API_KEY = 'your-api-key-here'
BASE_URL = 'http://localhost:3000'

def get_monthly_stats():
    params = {
        'startDate': '2026-04-01T00:00:00Z',
        'endDate': '2026-04-30T23:59:59Z',
        'grouping': 'daily',
        'breakdownByAsset': 'true',
    }
    
    headers = {'X-API-Key': API_KEY}
    
    try:
        response = requests.get(f'{BASE_URL}/analytics/stats', params=params, headers=headers)
        response.raise_for_status()
        
        data = response.json()
        print(f"Summary Volume: {data['summary']['totalVolume']}")
        print(f"Time Series Points: {len(data['timeSeries'])}")
        print(f"Execution Time: {data['metadata']['executionTimeMs']}ms")
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")

def compare_periods():
    today = datetime.utcnow()
    week_ago = today - timedelta(days=7)
    
    params = {
        'startDate': week_ago.isoformat() + 'Z',
        'endDate': today.isoformat() + 'Z',
        'grouping': 'weekly',
    }
    
    headers = {'X-API-Key': API_KEY}
    
    try:
        response = requests.get(f'{BASE_URL}/analytics/stats/comparison', params=params, headers=headers)
        response.raise_for_status()
        
        data = response.json()
        print(f"Volume Change: {data['comparison']['volumeChangePercent']}%")
        print(f"Success Rate Change: {data['comparison']['successRateChangePercent']}%")
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")

if __name__ == '__main__':
    get_monthly_stats()
    compare_periods()
```

---

## FAQ

**Q: What's the difference between totalActiveLinks and totalPaidLinks?**  
A: Active links have at least one transaction attempt (any status). Paid links have at least one successful transaction. A link can be active but not paid if all attempts failed.

**Q: Why are some metrics showing 0?**  
A: This happens when:
- No transactions in the period
- All transactions failed/are still pending
- The requested assets had no activity

Use `includeZeros=false` to omit zero-value periods.

**Q: Can I query data before January 2026?**  
A: No, platform analytics began tracking transactions in January 2026.

**Q: How often are materialized views refreshed?**  
A: Daily views hourly, weekly views every 6 hours, monthly views every 12 hours. For real-time precision, query transaction data directly.

**Q: What happens if an organization has no transactions?**  
A: All metrics return 0; time series includes all periods with empty data.

---

## Support

For issues or questions:

1. Check the [ERROR-CODES.md](../../docs/ERROR-CODES.md) for detailed error descriptions
2. Review [API-REFERENCE-PUBLIC-PROFILES.md](../../docs/API-REFERENCE-PUBLIC-PROFILES.md) for related auth endpoints
3. Contact support: api-support@quickex.to
