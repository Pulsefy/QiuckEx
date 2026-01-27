# Horizon Usage Guidelines

This document outlines how to fetch Stellar transaction data via Horizon in the QuickEx backend.

## Overview

The `HorizonService` provides a centralized way to interact with the Stellar Horizon API. It uses the `stellar-sdk` and implements in-memory caching to reduce latency and avoid rate limits.

## Fetching Payments

To get reliable amount and asset data, we fetch **operations** of type `payment`, `path_payment_strict_receive`, and `path_payment_strict_send` rather than raw transactions.

### Endpoint

`GET /transactions`

### Query Parameters

| Parameter | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `accountId` | string | Yes | Stellar public key (G...) |
| `asset` | string | No | Filter by asset (`XLM` or `CODE:ISSUER`) |
| `limit` | number | No | Max items to return (1-200, default 20) |
| `cursor` | string | No | Pagination token (`paging_token`) |

## Caching

Results are cached for **60 seconds** in memory using an LRU cache. The cache key includes the network, account ID, asset filter, limit, and cursor.

## Rate Limiting

If Horizon returns a `429 Too Many Requests` error, the backend will return a `503 Service Unavailable` response. Clients should implement their own backoff strategy and avoid aggressive polling.

## Example Usage

```typescript
// In a controller or service
const transactions = await this.horizonService.getPayments(
  'GD...',
  'USDC:GA...',
  20,
  '123456789'
);
```

## Best Practices

1.  **Always use the operations endpoint** for payment data.
2.  **Use pagination** instead of high limits to avoid long response times.
3.  **Validate account IDs** using `StrKey.isValidEd25519PublicKey`.
