# QuickEx SDK — Cookbook

> Practical, copy-pasteable examples for common integration tasks.

---

## Table of Contents

1. [Creating Payment Links](#creating-payment-links)
2. [Handling Webhooks](#handling-webhooks)
3. [Querying Transactions](#querying-transactions)
4. [Managing Usernames](#managing-usernames)
5. [Recurring Payments](#recurring-payments)
6. [Path Payments & Quotes](#path-payments--quotes)
7. [Marketplace Operations](#marketplace-operations)
8. [Fiat On/Off Ramps](#fiat-onoff-ramps)
9. [Bulk Operations](#bulk-operations)
10. [Admin Operations](#admin-operations)

---

## Creating Payment Links

### Basic Payment Link

Create a simple payment link with a fixed amount and asset:

```typescript
const response = await fetch('http://localhost:3000/links/metadata', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-API-Key': 'qk_live_abc123...',
  },
  body: JSON.stringify({
    amount: 50.5,
    asset: 'XLM',
    username: 'alice_123',
  }),
});

const { success, data } = await response.json();
console.log(data.canonical);
// "amount=50.5000000&asset=XLM&username=alice_123"
console.log(data.amount);
// "50.5000000"
```

### Payment Link with Memo and Expiration

```typescript
const response = await fetch('http://localhost:3000/links/metadata', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    amount: 100,
    asset: 'USDC',
    username: 'bob',
    memo: 'Invoice #INV-2025-042',
    memoType: 'text',
    expirationDays: 30,
    referenceId: 'INV-2025-042',
  }),
});

const { data } = await response.json();
console.log(data.expiresAt);
// "2026-05-28T12:00:00.000Z"
console.log(data.referenceId);
// "INV-2025-042"
```

### Multi-Asset Payment Link (Accept XLM or USDC)

```typescript
const response = await fetch('http://localhost:3000/links/metadata', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    amount: 50,
    asset: 'XLM',
    username: 'merchant_store',
    acceptedAssets: ['XLM', 'USDC'],
  }),
});

const { data } = await response.json();
console.log(data.acceptedAssets);
// ["XLM", "USDC"]
console.log(data.swapOptions);
// Array of path previews showing XLM↔USDC conversion rates
```

### Private Payment Link (X-Ray Privacy)

```typescript
const response = await fetch('http://localhost:3000/links/metadata', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    amount: 1000,
    asset: 'XLM',
    destination: 'GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR',
    privacy: true,
    memo: 'Confidential payment',
  }),
});

const { data } = await response.json();
console.log(data.privacy);
// true — amounts and sender are hidden
```

### Check Payment Link Status

```typescript
const params = new URLSearchParams({
  username: 'alice_123',
  amount: '50.5',
  asset: 'XLM',
});

const response = await fetch(`http://localhost:3000/payment-links/status?${params}`);
const status = await response.json();

console.log(status.state);         // "ACTIVE" | "EXPIRED" | "PAID" | "REFUNDED"
console.log(status.userMessage);   // "This payment link is active and ready to receive payment"
console.log(status.availableActions); // ["pay", "share"]

if (status.state === 'PAID') {
  console.log(status.transactionHash);
  console.log(status.paidAt);
}
```

### Scan a Link for Scam Indicators

```typescript
const response = await fetch('http://localhost:3000/links/scan', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    assetCode: 'USDC',
    amount: 10000,
    memo: 'URGENT PAYMENT REQUIRED',
    recipientAddress: 'GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR',
  }),
});

const result = await response.json();
console.log(result.riskScore);    // 0-100
console.log(result.flags);        // ["HIGH_AMOUNT", "URGENT_MEMO"]
console.log(result.recommendation); // "CAUTION" | "SAFE" | "DANGEROUS"
```

---

## Handling Webhooks

### Register a Webhook

```typescript
const publicKey = 'GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR';

const response = await fetch(`http://localhost:3000/webhooks/${publicKey}`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    webhookUrl: 'https://example.com/webhooks/quickex',
    label: 'Production webhook',
    events: ['payment.received', 'EscrowDeposited', 'EscrowWithdrawn'],
    minAmountStroops: 100000000, // 1 XLM minimum
  }),
});

const webhook = await response.json();
console.log(webhook.id);
console.log(webhook.secret);
// ⚠️ Save the secret — used to verify webhook signatures
```

### Register a Webhook for All Events

```typescript
const response = await fetch(`http://localhost:3000/webhooks/${publicKey}`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    webhookUrl: 'https://example.com/webhooks/quickex',
    events: null, // null = all events
  }),
});
```

### Verify Webhook Signatures (Node.js)

```typescript
import { createHmac, timingSafeEqual } from 'crypto';

function verifyQuickExWebhook(
  rawBody: string,
  signatureHeader: string,
  secret: string,
): boolean {
  const expected = createHmac('sha256', secret)
    .update(rawBody)
    .digest('hex');

  try {
    return timingSafeEqual(
      Buffer.from(signatureHeader),
      Buffer.from(expected),
    );
  } catch {
    return false;
  }
}
```

### Express.js Webhook Handler

```typescript
import express from 'express';
import { createHmac, timingSafeEqual } from 'crypto';

const app = express();

// Use raw body parser for webhook verification
app.use('/webhooks', express.raw({ type: 'application/json' }));

app.post('/webhooks/quickex', (req, res) => {
  const signature = req.headers['x-quickex-signature'] as string;
  const secret = process.env.QUICKEX_WEBHOOK_SECRET!;
  const rawBody = req.body.toString();

  // Verify signature
  const expected = createHmac('sha256', secret)
    .update(rawBody)
    .digest('hex');

  if (!timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) {
    return res.status(401).json({ error: 'Invalid signature' });
  }

  const event = JSON.parse(rawBody);

  // Process based on event type
  switch (event.type) {
    case 'payment.received':
      handlePaymentReceived(event.data);
      break;
    case 'EscrowDeposited':
      handleEscrowDeposit(event.data);
      break;
    case 'EscrowWithdrawn':
      handleEscrowWithdrawal(event.data);
      break;
    case 'EscrowRefunded':
      handleEscrowRefund(event.data);
      break;
    case 'recurring.payment.executed':
      handleRecurringPayment(event.data);
      break;
    case 'recurring.payment.failed':
      handleRecurringFailure(event.data);
      break;
    case 'username.claimed':
      handleUsernameClaimed(event.data);
      break;
    default:
      console.log('Unhandled event type:', event.type);
  }

  // Always return 200 quickly
  res.status(200).json({ received: true });
});

function handlePaymentReceived(data: any) {
  console.log(`Payment received: ${data.amount} ${data.asset} from ${data.from}`);
}

function handleEscrowDeposit(data: any) {
  console.log(`Escrow deposited: ${data.amount} ${data.asset}`);
}

function handleRecurringPayment(data: any) {
  console.log(`Recurring payment executed: period ${data.periodNumber}, tx: ${data.transactionHash}`);
}

function handleRecurringFailure(data: any) {
  console.error(`Recurring payment failed: ${data.failureReason}, retries: ${data.retryCount}`);
}

app.listen(3001, () => console.log('Webhook server running on :3001'));
```

### Next.js API Route Handler

```typescript
// app/api/webhooks/quickex/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { createHmac } from 'crypto';

export async function POST(request: NextRequest) {
  const rawBody = await request.text();
  const signature = request.headers.get('x-quickex-signature') || '';
  const secret = process.env.QUICKEX_WEBHOOK_SECRET!;

  // Verify signature
  const expected = createHmac('sha256', secret)
    .update(rawBody)
    .digest('hex');

  if (signature !== expected) {
    return NextResponse.json({ error: 'Invalid signature' }, { status: 401 });
  }

  const event = JSON.parse(rawBody);

  // Process event asynchronously
  processEvent(event).catch(console.error);

  return NextResponse.json({ received: true });
}

async function processEvent(event: any) {
  // Your business logic here
  console.log(`Processing ${event.type}:`, event.data);
}
```

### List Webhook Delivery Logs

```typescript
const publicKey = 'GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR';
const webhookId = 'abc-123-def';

const response = await fetch(
  `http://localhost:3000/webhooks/${publicKey}/${webhookId}/logs?limit=50`
);
const { data } = await response.json();

for (const log of data) {
  console.log(`${log.eventType}: ${log.status} (attempts: ${log.attempts})`);
  if (log.lastError) {
    console.log(`  Error: ${log.lastError}`);
  }
}
```

### Redeliver a Failed Webhook

```typescript
const response = await fetch(
  `http://localhost:3000/webhooks/${publicKey}/${webhookId}/redeliver`,
  {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      eventId: 'tx_abc123',
      eventType: 'payment.received',
    }),
  }
);

const result = await response.json();
console.log(result.queued);   // true if redelivery was triggered
console.log(result.message);  // "Event redelivery triggered successfully"
```

### Regenerate a Webhook Secret

```typescript
const response = await fetch(
  `http://localhost:3000/webhooks/${publicKey}/${webhookId}/regenerate-secret`,
  { method: 'POST' }
);

const { secret } = await response.json();
// ⚠️ Update your env vars — the old secret is now invalid
```

---

## Querying Transactions

### Get Recent Transactions for an Account

```typescript
const accountId = 'GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR';

const response = await fetch(
  `http://localhost:3000/transactions?accountId=${accountId}&limit=20`,
  {
    headers: { 'X-API-Key': 'qk_live_abc123...' },
  }
);

const { transactions, pagination } = await response.json();

for (const tx of transactions) {
  console.log(`${tx.timestamp} | ${tx.type} | ${tx.amount} ${tx.assetCode || 'XLM'}`);
  if (tx.destinationAccount) {
    console.log(`  → ${tx.destinationAccount}`);
  }
  if (tx.memo) {
    console.log(`  Memo: ${tx.memo}`);
  }
}

console.log('Has more:', pagination.hasMore);
console.log('Next cursor:', pagination.cursor);
```

### Filter Transactions by Asset

```typescript
const response = await fetch(
  `http://localhost:3000/transactions?accountId=${accountId}&asset=USDC&limit=50`
);
const { transactions } = await response.json();
// Only USDC transactions
```

### Paginate Through All Transactions

```typescript
async function getAllTransactions(accountId: string): Promise<any[]> {
  const all: any[] = [];
  let cursor: string | undefined;
  let hasMore = true;

  while (hasMore) {
    const params = new URLSearchParams({
      accountId,
      limit: '200',
    });
    if (cursor) params.set('cursor', cursor);

    const response = await fetch(`http://localhost:3000/transactions?${params}`, {
      headers: { 'X-API-Key': 'qk_live_abc123...' },
    });

    const { transactions, pagination } = await response.json();
    all.push(...transactions);
    hasMore = pagination.hasMore;
    cursor = pagination.cursor;

    // Respect rate limits
    if (hasMore) {
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
  }

  return all;
}
```

### Get Recent Payments (with Time Filter)

```typescript
const params = new URLSearchParams({
  address: accountId,
  since: '2026-04-01T00:00:00Z',
  limit: '50',
});

const response = await fetch(`http://localhost:3000/payments/recent?${params}`);
const { items } = await response.json();
// Payments since April 1st, 2026
```

---

## Managing Usernames

### Claim a Username

```typescript
const response = await fetch('http://localhost:3000/username', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    username: 'alice_123',
    publicKey: 'GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR',
  }),
});

if (response.ok) {
  const { ok } = await response.json();
  console.log('Username claimed:', ok); // true
} else {
  const error = await response.json();
  if (error.error?.code === 'USERNAME_TAKEN') {
    console.log('Username is already taken');
  } else if (error.error?.code === 'USERNAME_INVALID') {
    console.log('Invalid username format');
  }
}
```

### List Usernames for a Wallet

```typescript
const publicKey = 'GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR';

const response = await fetch(`http://localhost:3000/username?publicKey=${publicKey}`);
const { usernames } = await response.json();

for (const u of usernames) {
  console.log(`@${u.username} (public: ${u.isPublic})`);
}
```

### Enable Public Profile for Discovery

```typescript
const response = await fetch('http://localhost:3000/username/toggle-public', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    username: 'alice_123',
    publicKey: 'GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR',
    isPublic: true,
  }),
});

const { ok } = await response.json();
console.log('Profile is now public:', ok);
```

### Search for Users

```typescript
const query = 'alice';
const response = await fetch(
  `http://localhost:3000/username/search?query=${encodeURIComponent(query)}&limit=5`
);
const { profiles, total, has_more, next_cursor } = await response.json();

for (const p of profiles) {
  console.log(`@${p.username} (score: ${p.similarityScore}%)`);
}
```

### Get Trending Creators

```typescript
const response = await fetch(
  `http://localhost:3000/username/trending?timeWindowHours=168&limit=10`
);
const { creators } = await response.json();

for (const c of creators) {
  console.log(`@${c.username}: $${c.transactionVolume} (${c.transactionCount} txs)`);
}
```

---

## Recurring Payments

### Create a Monthly Subscription

```typescript
const response = await fetch('http://localhost:3000/links/recurring', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    amount: 9.99,
    asset: 'USDC',
    username: 'saas_provider',
    frequency: 'monthly',
    startDate: '2026-05-01T00:00:00Z',
    totalPeriods: 12,
    memo: 'Pro Plan Subscription',
    referenceId: 'SUB-2026-001',
  }),
});

const { success, data } = await response.json();
console.log('Subscription created:', data.id);
console.log('Next payment:', data.nextExecutionDate);
console.log('Status:', data.status); // "active"
```

### Create an Indefinite Weekly Payment

```typescript
const response = await fetch('http://localhost:3000/links/recurring', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    amount: 50,
    asset: 'XLM',
    destination: 'GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR',
    frequency: 'weekly',
    // No totalPeriods = indefinite
    // No endDate = indefinite
  }),
});
```

### Pause and Resume a Subscription

```typescript
// Pause
await fetch(`http://localhost:3000/links/recurring/${linkId}/pause`, {
  method: 'POST',
});

// Resume later
await fetch(`http://localhost:3000/links/recurring/${linkId}/resume`, {
  method: 'POST',
});
```

### Cancel a Subscription

```typescript
const response = await fetch(`http://localhost:3000/links/recurring/${linkId}/cancel`, {
  method: 'POST',
});

const { data } = await response.json();
console.log('Status:', data.status); // "cancelled"
```

### Update Subscription Amount

```typescript
const response = await fetch(`http://localhost:3000/links/recurring/${linkId}`, {
  method: 'PATCH',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    amount: 14.99, // Price increase
    memo: 'Pro Plan - Updated Pricing',
  }),
});
```

### Check Execution History

```typescript
const response = await fetch(
  `http://localhost:3000/links/recurring/${linkId}/executions`
);
const { data } = await response.json();

for (const exec of data) {
  console.log(`Period ${exec.periodNumber}: ${exec.status}`);
  if (exec.status === 'success') {
    console.log(`  TX: ${exec.transactionHash}`);
  } else if (exec.status === 'failed') {
    console.log(`  Error: ${exec.failureReason} (retries: ${exec.retryCount})`);
  }
}
```

### List Active Subscriptions

```typescript
const response = await fetch(
  `http://localhost:3000/links/recurring?status=active&limit=50`
);
const { data, total, has_more, next_cursor } = await response.json();
console.log(`Found ${total} active subscriptions`);
```

---

## Path Payments & Quotes

### Get Verified Assets

```typescript
const response = await fetch('http://localhost:3000/stellar/verified-assets');
const { assets } = await response.json();

for (const asset of assets) {
  console.log(`${asset.code} - ${asset.description}`);
}
```

### Strict-Receive Path Preview

Find how much the sender needs to send for the recipient to receive exactly 10 USDC:

```typescript
const response = await fetch('http://localhost:3000/stellar/path-preview', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    destinationAmount: '10',
    destinationAsset: { code: 'USDC', issuer: 'GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN' },
    sourceAssets: [
      { code: 'XLM' },
      { code: 'AQUA', issuer: '...' },
    ],
  }),
});

const paths = await response.json();
for (const path of paths) {
  console.log(`Send ${path.sourceAmount} ${path.sourceAsset} → Receive 10 USDC`);
  console.log(`  Rate: ${path.rateDescription}`);
  console.log(`  Hops: ${path.hopCount}`);
}
```

### Strict-Send Path Preview

Find how much the recipient gets if the sender sends exactly 100 XLM:

```typescript
const response = await fetch('http://localhost:3000/stellar/path-preview/strict-send', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    sourceAmount: '100',
    sourceAsset: { code: 'XLM' },
    destinationAssets: [
      { code: 'USDC', issuer: 'GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN' },
    ],
  }),
});
```

### Create a Quote with Slippage Protection

```typescript
const response = await fetch('http://localhost:3000/stellar/quote', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    destinationAmount: '100',
    destinationAsset: { code: 'USDC', issuer: 'GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN' },
    sourceAssets: [{ code: 'XLM' }],
    maxSlippageBps: 100, // 1% slippage tolerance
    ttlSeconds: 60,      // Quote valid for 60 seconds
    preflight: true,     // Run Soroban simulation
  }),
});

const quote = await response.json();
console.log('Quote ID:', quote.quoteId);
console.log('Expires:', quote.expiresAt);

for (const path of quote.paths) {
  console.log(`Send ${path.sourceAmount} XLM (max: ${path.sourceAmountWithSlippage})`);
}

if (quote.preflight) {
  console.log('Preflight feasible:', quote.preflight.feasible);
}
```

### Retrieve a Quote

```typescript
const response = await fetch(`http://localhost:3000/stellar/quote/${quoteId}`);

if (response.status === 410) {
  console.log('Quote has expired');
} else {
  const quote = await response.json();
  // Use the quote details
}
```

---

## Marketplace Operations

### List a Username for Sale

```typescript
const response = await fetch('http://localhost:3000/marketplace/list', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    username: 'premium_name',
    sellerPublicKey: 'GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR',
    askingPrice: 500,
  }),
});

const { listing } = await response.json();
console.log('Listing ID:', listing.id);
```

### Browse Active Listings

```typescript
const response = await fetch('http://localhost:3000/marketplace?limit=20');
const { listings, total } = await response.json();

for (const l of listings) {
  console.log(`@${l.username} - ${l.askingPrice} XLM`);
}
```

### Place a Bid

```typescript
const response = await fetch(`http://localhost:3000/marketplace/${listingId}/bid`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    bidderPublicKey: 'GDIFFERENTKEY...',
    bidAmount: 450,
  }),
});

const { bid } = await response.json();
console.log('Bid placed:', bid.id);
```

### Accept a Bid (Transfers Ownership)

```typescript
const response = await fetch(
  `http://localhost:3000/marketplace/${listingId}/accept-bid/${bidId}`,
  {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      sellerPublicKey: 'GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR',
    }),
  }
);

const { ok } = await response.json();
console.log('Ownership transferred:', ok);
```

---

## Fiat On/Off Ramps

### Find Available Anchors

```typescript
const response = await fetch(
  `http://localhost:3000/fiat-ramps/anchors?assetCode=USDC&country=US`
);
const anchors = await response.json();
```

### Initiate a Deposit (Buy Crypto)

```typescript
const response = await fetch('http://localhost:3000/fiat-ramps/deposit', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    assetCode: 'USDC',
    amount: 100,
    userAccount: 'GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR',
    anchorDomain: 'anchor.example.com',
  }),
});
```

### Initiate a Withdrawal (Sell Crypto)

```typescript
const response = await fetch('http://localhost:3000/fiat-ramps/withdraw', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    assetCode: 'USDC',
    amount: 50,
    userAccount: 'GBXGQ55JMQ4L2B6E7S8Y9Z0A1B2C3D4E5F6G7H8I7YWR',
    anchorDomain: 'anchor.example.com',
  }),
});
```

---

## Bulk Operations

### Bulk Generate Payment Links (JSON)

```typescript
const links = [];
for (let i = 0; i < 100; i++) {
  links.push({
    amount: 10 + i * 0.5,
    asset: 'XLM',
    username: 'payroll_recipient',
    memo: `Salary-${i + 1}`,
    referenceId: `PAY-${String(i + 1).padStart(4, '0')}`,
  });
}

const response = await fetch('http://localhost:3000/links/bulk/generate', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ links }),
});

const result = await response.json();
console.log(`Generated ${result.total} links in ${result.processingTimeMs}ms`);

for (const link of result.links) {
  console.log(`${link.referenceId}: ${link.url}`);
}
```

### Bulk Generate from CSV (Node.js)

```typescript
import { readFileSync } from 'fs';
import FormData from 'form-data';

const csvContent = readFileSync('payroll.csv', 'utf-8');

const response = await fetch('http://localhost:3000/links/bulk/generate/csv', {
  method: 'POST',
  body: (() => {
    const form = new FormData();
    form.append('file', csvContent, { filename: 'payroll.csv', contentType: 'text/csv' });
    return form;
  })(),
});
```

**Example CSV:**

```csv
amount,asset,memo,username,referenceId,expirationDays
50.5,XLM,Invoice-001,alice_123,INV-001,30
100,USDC,Invoice-002,bob,INV-002,14
75,XLM,Invoice-003,charlie,INV-003,7
```

---

## Admin Operations

### Create an API Key

```typescript
const response = await fetch('http://localhost:3000/api-keys', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    name: 'Production Integration',
    scopes: ['links:read', 'links:write', 'transactions:read'],
    owner_id: 'user-uuid-here',
  }),
});

const apiKey = await response.json();
console.log('Key:', apiKey.key);       // ⚠️ Save now — shown only once!
console.log('Prefix:', apiKey.key_prefix); // "qk_live_****"
console.log('ID:', apiKey.id);
```

### Rotate an API Key

```typescript
const response = await fetch(`http://localhost:3000/api-keys/${apiKeyId}/rotate`, {
  method: 'POST',
});

const result = await response.json();
console.log('New key:', result.key); // Old key is now invalid
```

### Revoke an API Key

```typescript
await fetch(`http://localhost:3000/api-keys/${apiKeyId}`, {
  method: 'DELETE',
});
```

### Initiate a Refund (Admin)

```typescript
const response = await fetch('http://localhost:3000/admin/refunds', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-API-Key': 'qk_live_admin_key...',
  },
  body: JSON.stringify({
    entityType: 'payment',
    entityId: 'payment-uuid',
    idempotencyKey: 'refund-' + crypto.randomUUID(),
    reasonCode: 'CUSTOMER_REQUEST',
    notes: 'Customer requested refund for duplicate charge',
  }),
});
```

### Request a Data Export

```typescript
const response = await fetch('http://localhost:3000/exports', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-API-Key': 'qk_live_abc123...',
  },
  body: JSON.stringify({
    userId: 'user-uuid-here',
    exportType: 'transactions',
    filters: {
      startDate: '2026-01-01',
      endDate: '2026-04-30',
    },
    format: 'csv',
    deliveryMethod: 'email',
  }),
});

const { jobId, message } = await response.json();
console.log('Export job:', jobId);
```

---

**Last Updated:** April 2026
**Version:** 1.0.0
