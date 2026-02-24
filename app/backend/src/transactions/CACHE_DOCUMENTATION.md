# Transactions Endpoint Caching and Resilience

## Overview

The transactions endpoint implements advanced caching and resilience mechanisms to improve performance and handle Horizon API failures gracefully.

## Caching Strategy

### Cache Configuration

The service uses an LRU (Least Recently Used) cache with the following configurable parameters:

- **CACHE_MAX_ITEMS**: Maximum number of cached entries (default: 500)
- **CACHE_TTL_MS**: Time-to-live for cached entries in milliseconds (default: 60000ms/60s)

### Cache Key Structure

Cache keys are generated using the following pattern:
```
{network}:{accountId}:{asset}:{limit}:{cursor}
```

Where:
- `network`: Stellar network (testnet/mainnet)
- `accountId`: Stellar account public key
- `asset`: Asset filter (or 'any' if no filter)
- `limit`: Number of records requested
- `cursor`: Pagination cursor (or 'start' if none)

### Cache Behavior

- **Cache Hit**: Returns cached data immediately without calling Horizon
- **Cache Miss**: Fetches fresh data from Horizon and caches the response
- **TTL Refresh**: Cache entries refresh their TTL on access (`updateAgeOnGet: true`)
- **LRU Eviction**: Least recently used entries are automatically removed when cache is full

## Resilience Features

### Exponential Backoff

When Horizon returns rate limit (429) or server errors (5xx), the service implements:

1. **Exponential Backoff**: Delay increases exponentially with each failure
2. **Full Jitter**: Random component added to prevent thundering herd
3. **Maximum Delay**: Capped at 30 seconds
4. **Attempt Tracking**: Up to 3 retry attempts per request

**Backoff Formula**:
```
delay = min(baseDelay * 2^(attempt-1), maxDelay) + random(0, delay)
```

### Error Handling

| HTTP Status | Behavior | Response |
|-------------|----------|----------|
| 429 | Rate limiting | SERVICE_UNAVAILABLE (503) |
| 500 | Internal error | BAD_GATEWAY (502) |
| 502-504 | Service unavailable | SERVICE_UNAVAILABLE (503) |
| 4xx | Client error | BAD_REQUEST (400) |

### Retry Logic

- **Retryable Errors**: 429, 5xx status codes
- **Non-retryable**: 4xx client errors
- **Max Retries**: 3 attempts
- **Backoff**: Applied between retry attempts

## Configuration

### Environment Variables

```bash
# Cache settings
CACHE_MAX_ITEMS=500        # Maximum cached entries
CACHE_TTL_MS=60000         # Cache TTL in milliseconds (60 seconds)

# Network settings
NETWORK=testnet            # or mainnet
```

### Production Recommendations

For production environments, consider these settings:

```bash
# Higher cache capacity for busy services
CACHE_MAX_ITEMS=2000

# Longer TTL for better performance
CACHE_TTL_MS=300000        # 5 minutes

# Adjust based on traffic patterns
# High traffic: Increase CACHE_MAX_ITEMS
# Real-time needs: Decrease CACHE_TTL_MS
```

## Monitoring

### Cache Statistics

The service exposes cache statistics via `getCacheStats()`:

```typescript
{
  entries: number,      // Current cached entries
  maxEntries: number,   // Maximum cache size
  ttl: number,          // Configured TTL in ms
  backoffEntries: number // Active backoff tracking entries
}
```

### Logging

Key events are logged:
- Cache hits/misses
- Backoff activation
- Retry attempts
- Error conditions

## Testing

### Cache Tests

- Cache hit/miss behavior
- TTL expiration
- LRU eviction
- Different query parameter caching

### Resilience Tests

- 429 rate limit handling
- 5xx server error handling
- Backoff mechanism
- Retry logic
- Error recovery

## Performance Benefits

### Expected Improvements

- **Reduced Latency**: Cached responses served in milliseconds
- **Lower Horizon Load**: Reduced API calls to Horizon service
- **Better Reliability**: Graceful degradation during outages
- **Improved User Experience**: Faster response times for repeated queries

### Cache Effectiveness

Cache hit rates depend on:
- Query patterns (repeated account queries)
- TTL settings
- Cache size
- User behavior

Monitor cache statistics to optimize configuration.

## Best Practices

1. **Cache Warming**: Consider pre-warming cache for high-traffic accounts
2. **TTL Tuning**: Adjust based on data freshness requirements
3. **Monitoring**: Track cache hit rates and backoff frequency
4. **Error Handling**: Implement client-side retry logic for 503 responses
5. **Pagination**: Use cursors effectively to leverage caching

## Troubleshooting

### Common Issues

**High cache miss rate**:
- Increase CACHE_MAX_ITEMS
- Check query parameter consistency
- Verify cache key generation

**Frequent backoff activation**:
- Check Horizon rate limits
- Review retry configuration
- Monitor error patterns

**Stale data**:
- Reduce CACHE_TTL_MS
- Implement cache invalidation strategy
- Consider cache warming for critical data

### Debugging

Enable debug logging to trace:
- Cache operations
- Backoff decisions
- Retry attempts
- Error handling