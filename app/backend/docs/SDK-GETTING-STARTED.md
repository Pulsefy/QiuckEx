# QuickEx SDK — Getting Started Guide

> A complete guide for integrating QuickEx into your JavaScript or TypeScript application.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [Authentication](#authentication)
5. [Quick Start](#quick-start)
6. [Core Concepts](#core-concepts)
7. [TypeScript Types](#typescript-types)
8. [Rate Limits](#rate-limits)
9. [Error Handling](#error-handling)
10. [Pagination](#pagination)
11. [Webhook Verification](#webhook-verification)
12. [SDK Reference](#sdk-reference)

---

## Prerequisites

- **Node.js** 18+ (or a modern browser with `fetch` support)
- **TypeScript** 5+ (optional, but recommended)
- A **Stellar wallet** (for signing and sending transactions)
- A **QuickEx API key** (optional — gives higher rate limits)

---

## Installation

### Option A: Install the client package (when published)

```bash
npm install @quickex/sdk
# or
pnpm add @quickex/sdk
# or
yarn add @quickex/sdk
```

### Option B: Use the lightweight HTTP client (zero dependencies)

The QuickEx API is a standard REST API. You can use `fetch` directly:

```bash
# No extra packages needed — just use the built-in fetch API
```

---

## Configuration

```typescript
// quickex.config.ts
export const QUICKEX_CONFIG = {
  // Base URL — change to https://api.quickex.example.com for production
  baseUrl: process.env.QUICKEX_BASE_URL || 'http://localhost:3000',

  // Optional API key for higher rate limits
  apiKey: process.env.QUICKEX_API_KEY || '',

  // Network — 'testnet' or 'mainnet'
  network: process.env.STELLAR_NETWORK || 'testnet',
};
```

### Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `QUICKEX_BASE_URL` | No | `http://localhost:3000` | API base URL |
| `QUICKEX_API_KEY` | No | — | API key for higher rate limits |
| `STELLAR_NETWORK` | No | `testnet` | Stellar network to use |

---

## Authentication

QuickEx uses API keys for authentication. API keys are optional for public endpoints but give you:

- **Higher rate limits**: 120 req/min vs 20 req/min
- **Access to admin endpoints**: refunds, exports, feature flags
- **Scoped permissions**: fine-grained access control

### Creating an API Key

```typescript
const response = await fetch('http://localhost:3000/api-keys', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    name: 'My App Key',
    scopes: ['links:read', 'links:write', 'transactions:read'],
  }),
});

const { key, id } = await response.json();
// ⚠️ Save `key` now — it's shown only once!
```

### Using an API Key

```typescript
const headers = {
  'Content-Type': 'application/json',
  'X-API-Key': 'qk_live_abc123...',
};
```

### Available Scopes

| Scope | Description |
|---|---|
| `links:read` | Read payment link metadata and status |
| `links:write` | Create and manage payment links |
| `transactions:read` | Query transaction history |
| `usernames:read` | Search and list usernames |
| `refunds:write` | Initiate and manage refunds (admin) |
| `admin` | Full admin access (job queue, feature flags) |

---

## Quick Start

### 1. Initialize the client

```typescript
class QuickExClient {
  private baseUrl: string;
  private apiKey?: string;

  constructor(baseUrl: string, apiKey?: string) {
    this.baseUrl = baseUrl;
    this.apiKey = apiKey;
  }

  private async request<T>(path: string, options: RequestInit = {}): Promise<T> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...(options.headers as Record<string, string>),
    };
    if (this.apiKey) {
      headers['X-API-Key'] = this.apiKey;
    }

    const response = await fetch(`${this.baseUrl}${path}`, {
      ...options,
      headers,
    });

    if (!response.ok) {
      const error = await response.json();
      throw new QuickExError(error);
    }

    return response.json();
  }

  // --- Health ---
  health() {
    return this.request<{ status: string }>('/health');
  }

  // --- Usernames ---
  createUsername(username: string, publicKey: string) {
    return this.request<{ ok: boolean }>('/username', {
      method: 'POST',
      body: JSON.stringify({ username, publicKey }),
    });
  }

  listUsernames(publicKey: string) {
    return this.request<{ usernames: any[] }>(`/username?publicKey=${publicKey}`);
  }

  searchUsernames(query: string, limit = 10) {
    return this.request<any>(`/username/search?query=${encodeURIComponent(query)}&limit=${limit}`);
  }

  // --- Links ---
  generateLinkMetadata(data: any) {
    return this.request<{ success: boolean; data: any }>('/links/metadata', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  getPaymentLinkStatus(params: { username: string; amount: number; asset?: string; memo?: string }) {
    const qs = new URLSearchParams({
      username: params.username,
      amount: String(params.amount),
      ...(params.asset && { asset: params.asset }),
      ...(params.memo && { memo: params.memo }),
    });
    return this.request<any>(`/payment-links/status?${qs}`);
  }

  // --- Transactions ---
  getTransactions(accountId: string, options?: { asset?: string; limit?: number; cursor?: string }) {
    const qs = new URLSearchParams({ accountId });
    if (options?.asset) qs.set('asset', options.asset);
    if (options?.limit) qs.set('limit', String(options.limit));
    if (options?.cursor) qs.set('cursor', options.cursor);
    return this.request<any>(`/transactions?${qs}`);
  }

  // --- Stellar ---
  getVerifiedAssets() {
    return this.request<any>('/stellar/verified-assets');
  }

  createQuote(data: any) {
    return this.request<any>('/stellar/quote', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  // --- Webhooks ---
  createWebhook(publicKey: string, data: any) {
    return this.request<any>(`/webhooks/${publicKey}`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  listWebhooks(publicKey: string) {
    return this.request<any>(`/webhooks/${publicKey}`);
  }

  deleteWebhook(publicKey: string, id: string) {
    return this.request<void>(`/webhooks/${publicKey}/${id}`, {
      method: 'DELETE',
    });
  }
}

// Custom error class
class QuickExError extends Error {
  code: string;
  requestId?: string;
  fields?: Record<string, string[]>;

  constructor(error: { error: { code: string; message: string; request_id?: string; fields?: Record<string, string[]> } }) {
    super(error.error.message);
    this.code = error.error.code;
    this.requestId = error.error.request_id;
    this.fields = error.error.fields;
    this.name = 'QuickExError';
  }
}
```

### 2. Use the client

```typescript
const client = new QuickExClient(
  'http://localhost:3000',
  'qk_live_abc123...' // optional
);

// Check health
const health = await client.health();
console.log(health.status); // "ok"

// Register a username
await client.createUsername('alice_123', 'GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR');

// Create a payment link
const link = await client.generateLinkMetadata({
  amount: 50.5,
  asset: 'XLM',
  username: 'alice_123',
  memo: 'Payment for service',
  acceptedAssets: ['XLM', 'USDC'],
});

// Query transactions
const txs = await client.getTransactions('GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR', {
  limit: 10,
});
```

---

## Core Concepts

### Payment Links

Payment links are the primary way to receive payments. A link encodes the recipient, amount, asset, and optional memo into a shareable URL.

**Lifecycle:**

```
DRAFT → ACTIVE → EXPIRED → (re-activated) → ACTIVE
                 → PAID → REFUNDED
```

**Link Format:**

```
https://app.quickex.example.com/pay?amount=50.5000000&asset=XLM&username=alice_123
```

### Usernames

Usernames map human-readable names to Stellar public keys. They replace raw `G...` addresses with `alice_123` style identifiers.

- 3-32 characters, lowercase alphanumeric + underscores
- Each wallet can have multiple usernames (configurable limit)
- Public profiles are opt-in and appear in search/trending

### Recurring Payments

Subscription-style payments that execute automatically at daily, weekly, monthly, or yearly intervals.

**Status flow:** `active → paused → active` or `active → cancelled`

### Marketplace

A marketplace for trading usernames. Sellers list usernames, buyers place bids, and the seller accepts a bid to atomically transfer ownership.

---

## TypeScript Types

```typescript
// --- Common ---
interface PaginatedResponse<T> {
  data: T[];
  next_cursor: string | null;
  has_more: boolean;
  limit: number;
}

// --- Username ---
interface Username {
  username: string;
  publicKey: string;
  isPublic: boolean;
}

interface PublicProfile {
  id: string;
  username: string;
  publicKey: string;
  similarityScore?: number;
  transactionVolume?: number;
  transactionCount?: number;
  lastActiveAt: string;
  createdAt: string;
}

// --- Payment Link ---
type LinkState = 'DRAFT' | 'ACTIVE' | 'EXPIRED' | 'PAID' | 'REFUNDED';

interface LinkMetadata {
  amount: string;           // "50.5000000" (7 decimal places)
  memo: string | null;
  memoType: string;
  asset: string;
  privacy: boolean;
  expiresAt: string | null;
  canonical: string;
  username?: string | null;
  destination?: string | null;
  referenceId?: string | null;
  acceptedAssets?: string[] | null;
  metadata: {
    normalized: boolean;
    warnings?: string[];
  };
}

interface PaymentLinkStatus {
  state: LinkState;
  username: string;
  amount: string;
  asset: string;
  memo: string | null;
  destinationPublicKey: string;
  expiresAt: string | null;
  transactionHash: string | null;
  paidAt: string | null;
  acceptsMultipleAssets: boolean;
  acceptedAssets: string[] | null;
  userMessage?: string;
  availableActions?: string[];
}

// --- Transaction ---
interface Transaction {
  hash: string;
  ledger: number;
  timestamp: string;
  sourceAccount: string;
  type: string;
  assetCode: string | null;
  assetIssuer: string | null;
  amount: string;
  destinationAccount: string | null;
  memo: string | null;
  memoType: string | null;
}

// --- Recurring Payment ---
type FrequencyType = 'daily' | 'weekly' | 'monthly' | 'yearly';
type RecurringStatus = 'active' | 'paused' | 'completed' | 'cancelled';

interface RecurringPaymentLink {
  id: string;
  username?: string;
  destination?: string;
  amount: number;
  asset: string;
  frequency: FrequencyType;
  startDate: string;
  endDate?: string;
  totalPeriods?: number;
  executedCount: number;
  nextExecutionDate: string;
  status: RecurringStatus;
  privacyEnabled: boolean;
  createdAt: string;
  updatedAt: string;
}

// --- Webhook ---
type NotificationEventType =
  | 'EscrowDeposited'
  | 'EscrowWithdrawn'
  | 'EscrowRefunded'
  | 'payment.received'
  | 'username.claimed'
  | 'recurring.payment.due'
  | 'recurring.payment.executed'
  | 'recurring.payment.failed'
  | 'recurring.payment.cancelled'
  | 'recurring.link.created'
  | 'recurring.link.updated'
  | 'recurring.link.paused'
  | 'recurring.link.resumed'
  | 'recurring.link.completed';

interface Webhook {
  id: string;
  publicKey: string;
  webhookUrl: string;
  label?: string;
  secret: string;
  events: NotificationEventType[] | null;
  minAmountStroops: string;
  enabled: boolean;
  createdAt: string;
  updatedAt: string;
}

// --- Quote ---
interface QuotePath {
  sourceAsset: string;
  sourceAmount: string;
  sourceAmountWithSlippage: string;
  destinationAsset: string;
  destinationAmount: string;
  pathHops: string[];
  rateDescription: string;
}

interface Quote {
  quoteId: string;
  paths: QuotePath[];
  expiresAt: string;
  maxSlippageBps: number;
  horizonUrl: string;
  preflight?: { feasible: boolean; error?: string };
}

// --- API Key ---
type ApiKeyScope = 'links:read' | 'links:write' | 'transactions:read' | 'usernames:read' | 'refunds:write' | 'admin';

interface ApiKeyCreated {
  id: string;
  name: string;
  key: string;           // ⚠️ Only shown once!
  key_prefix: string;
  scopes: ApiKeyScope[];
  is_active: boolean;
}
```

---

## Rate Limits

| Tier | Default (no key) | With API Key |
|---|---|---|
| Global | 20 req/min | 120 req/min |
| Search | 20 req/min | 120 req/min |
| Trending | 10 req/min | 120 req/min |

When rate-limited, you receive a `429` response:

```json
{
  "success": false,
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Too many requests. Retry after 30 seconds.",
    "request_id": "uuid-here",
    "details": { "retryAfterSeconds": 30 }
  }
}
```

### Retry Strategy

```typescript
async function requestWithRetry<T>(
  fn: () => Promise<T>,
  maxRetries = 3,
): Promise<T> {
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await fn();
    } catch (error) {
      if (error instanceof QuickExError && error.code === 'RATE_LIMIT_EXCEEDED') {
        const retryAfter = 30; // seconds
        if (attempt < maxRetries) {
          await new Promise(resolve => setTimeout(resolve, retryAfter * 1000));
          continue;
        }
      }
      throw error;
    }
  }
  throw new Error('Max retries exceeded');
}
```

---

## Error Handling

All errors follow the same JSON shape. See the [Error Contract](./ERROR-CODES.md) for the full reference.

```typescript
try {
  await client.createUsername('taken_name', publicKey);
} catch (error) {
  if (error instanceof QuickExError) {
    switch (error.code) {
      case 'USERNAME_TAKEN':
        // Username already registered
        break;
      case 'USERNAME_INVALID':
        // Format requirements not met
        break;
      case 'VALIDATION_ERROR':
        // Check error.fields for details
        console.log(error.fields);
        break;
      default:
        // Handle other errors
        console.error(`Error [${error.code}]: ${error.message}`);
    }
  }
}
```

---

## Pagination

QuickEx uses cursor-based pagination for list endpoints. Pass the `cursor` from a previous response to get the next page.

```typescript
async function getAllTransactions(client: QuickExClient, accountId: string): Promise<Transaction[]> {
  const all: Transaction[] = [];
  let cursor: string | undefined;

  do {
    const response = await client.getTransactions(accountId, {
      limit: 100,
      cursor,
    });

    all.push(...response.transactions);
    cursor = response.pagination.hasMore ? response.pagination.cursor : undefined;
  } while (cursor);

  return all;
}
```

---

## Webhook Verification

When you register a webhook, QuickEx signs every payload with a secret. Verify signatures to ensure authenticity.

```typescript
import { createHmac } from 'crypto';

function verifyWebhookSignature(
  payload: string,     // raw request body
  signature: string,   // x-quickex-signature header
  secret: string,      // from webhook registration response
): boolean {
  const expected = createHmac('sha256', secret)
    .update(payload)
    .digest('hex');
  return signature === expected;
}

// Express example
app.post('/webhooks/quickex', (req, res) => {
  const signature = req.headers['x-quickex-signature'] as string;
  const raw = JSON.stringify(req.body); // use raw body parser in production
  const secret = process.env.QUICKEX_WEBHOOK_SECRET!;

  if (!verifyWebhookSignature(raw, signature, secret)) {
    return res.status(401).json({ error: 'Invalid signature' });
  }

  // Process the verified event
  console.log('Verified event:', req.body);
  res.status(200).json({ received: true });
});
```

---

## SDK Reference

### Endpoints Quick Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Health check |
| `GET` | `/ready` | Readiness check |
| `POST` | `/username` | Create username |
| `GET` | `/username` | List usernames for wallet |
| `GET` | `/username/search` | Search public profiles |
| `GET` | `/username/trending` | Trending creators |
| `GET` | `/username/recently-active` | Recently active users |
| `POST` | `/username/toggle-public` | Toggle profile visibility |
| `POST` | `/links/metadata` | Generate link metadata |
| `POST` | `/links/bulk/generate` | Bulk link generation (JSON) |
| `POST` | `/links/bulk/generate/csv` | Bulk link generation (CSV) |
| `GET` | `/payment-links/status` | Payment link status |
| `POST` | `/links/recurring` | Create recurring link |
| `GET` | `/links/recurring` | List recurring links |
| `GET` | `/links/recurring/:id` | Get recurring link |
| `PATCH` | `/links/recurring/:id` | Update recurring link |
| `POST` | `/links/recurring/:id/cancel` | Cancel recurring link |
| `POST` | `/links/recurring/:id/pause` | Pause recurring link |
| `POST` | `/links/recurring/:id/resume` | Resume recurring link |
| `GET` | `/links/recurring/:id/executions` | Execution history |
| `POST` | `/links/scan` | Scan link for scams |
| `GET` | `/transactions` | List transactions |
| `POST` | `/transactions/compose` | Compose Soroban tx |
| `GET` | `/payments/recent` | Recent payments |
| `GET` | `/stellar/verified-assets` | Verified assets |
| `POST` | `/stellar/path-preview` | Path preview (strict-receive) |
| `POST` | `/stellar/path-preview/strict-send` | Path preview (strict-send) |
| `POST` | `/stellar/soroban-preflight` | Soroban preflight |
| `POST` | `/stellar/quote` | Create quote |
| `GET` | `/stellar/quote/:quoteId` | Get quote |
| `POST` | `/webhooks/:publicKey` | Register webhook |
| `GET` | `/webhooks/:publicKey` | List webhooks |
| `GET` | `/webhooks/:publicKey/:id` | Get webhook |
| `PUT` | `/webhooks/:publicKey/:id` | Update webhook |
| `DELETE` | `/webhooks/:publicKey/:id` | Delete webhook |
| `POST` | `/webhooks/:publicKey/:id/regenerate-secret` | Regenerate secret |
| `GET` | `/webhooks/:publicKey/:id/logs` | Delivery logs |
| `GET` | `/webhooks/:publicKey/:id/stats` | Delivery stats |
| `POST` | `/webhooks/:publicKey/:id/redeliver` | Redeliver event |
| `PUT` | `/notifications/preferences/:publicKey` | Set notification prefs |
| `GET` | `/notifications/preferences/:publicKey` | Get notification prefs |
| `DELETE` | `/notifications/preferences/:publicKey/:channel` | Disable channel |
| `POST` | `/marketplace/list` | List username for sale |
| `GET` | `/marketplace` | Active listings |
| `GET` | `/marketplace/:listingId` | Get listing |
| `DELETE` | `/marketplace/:listingId` | Cancel listing |
| `POST` | `/marketplace/:listingId/bid` | Place bid |
| `GET` | `/marketplace/:listingId/bids` | Get bids |
| `POST` | `/marketplace/:listingId/accept-bid/:bidId` | Accept bid |
| `POST` | `/api-keys` | Create API key |
| `GET` | `/api-keys` | List API keys |
| `GET` | `/api-keys/usage` | Usage stats |
| `DELETE` | `/api-keys/:id` | Revoke key |
| `POST` | `/api-keys/:id/rotate` | Rotate key |
| `GET` | `/fiat-ramps/anchors` | Available anchors |
| `POST` | `/fiat-ramps/deposit` | Initiate deposit |
| `POST` | `/fiat-ramps/withdraw` | Initiate withdrawal |
| `POST` | `/admin/refunds` | Initiate refund |
| `GET` | `/admin/refunds` | List refunds |
| `POST` | `/admin/refunds/:id/approve` | Approve refund |
| `POST` | `/admin/refunds/:id/reject` | Reject refund |
| `POST` | `/exports` | Request data export |
| `GET` | `/telegram/status/:telegramId` | Check Telegram linkage |
| `POST` | `/telegram/verify/:telegramId` | Verify Telegram linkage |
| `PUT` | `/telegram/settings/:telegramId` | Update Telegram settings |
| `DELETE` | `/telegram/link/:telegramId` | Unlink Telegram |
| `GET` | `/reconciliation/status` | Reconciliation worker status |
| `POST` | `/reconciliation/trigger` | Trigger reconciliation |
| `POST` | `/reconciliation/backfill` | Start backfill |
| `GET` | `/reconciliation/backfill/status` | Backfill progress |
| `GET` | `/admin/jobs` | List jobs |
| `GET` | `/admin/jobs/metrics/summary` | Job metrics |
| `GET` | `/admin/jobs/dlq` | Dead letter queue |
| `POST` | `/admin/jobs/bulk-retry` | Bulk retry jobs |
| `GET` | `/admin/jobs/:id` | Get job details |
| `POST` | `/admin/jobs/:id/cancel` | Cancel job |
| `POST` | `/admin/jobs/:id/retry` | Retry job |
| `GET` | `/metrics` | Prometheus metrics |
| `GET` | `/metrics/content-type` | Metrics content type |
| `GET` | `/assets` | List assets with metadata |
| `GET` | `/assets/:code` | Get asset metadata |
| `POST` | `/assets/:code/refresh` | Refresh asset cache |
| `GET` | `/assets/cache/stats` | Cache stats |
| `POST` | `/assets/cache/clear` | Clear cache |
| `GET` | `/admin/audit` | Query audit logs |
| `GET` | `/admin/audit/export` | Export audit CSV |
| `DELETE` | `/admin/audit/retention` | Apply retention policy |

---

**Last Updated:** April 2026
**Version:** 1.0.0
