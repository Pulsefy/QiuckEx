/**
 * Deterministic seed fixtures for integration tests.
 * Each entity is assigned a stable, human-readable ID. Use `createSeedFixtures`
 * with a prefix to namespace data for per-test isolation.
 */

export interface SeedUser {
  id: string;
  username: string;
  email: string;
}

export interface SeedUsername {
  id: string;
  username: string;
  user_id: string;
}

export interface SeedLink {
  id: string;
  user_id: string;
  url: string;
  alias: string;
  created_at: string;
}

export interface SeedTransaction {
  id: string;
  user_id: string;
  amount: number;
  currency: string;
  status: string;
}

export interface SeedReceipt {
  id: string;
  transaction_id: string;
  url: string;
  created_at: string;
}

export interface SeedFixtures {
  users: SeedUser[];
  usernames: SeedUsername[];
  links: SeedLink[];
  transactions: SeedTransaction[];
  receipts: SeedReceipt[];
}

/**
 * Builds the canonical dataset. When an idPrefix is supplied, it is prepended
 * to every primary/foreign key so tests can run without colliding.
 */
export function createSeedFixtures(idPrefix = ''): SeedFixtures {
  const p = (value: string) => `${idPrefix}${value}`;

  return {
    users: [
      {
        id: p('user_001'),
        username: 'alice',
        email: 'alice@example.com',
      },
      {
        id: p('user_002'),
        username: 'bob',
        email: 'bob@example.com',
      },
      {
        id: p('user_003'),
        username: 'carol',
        email: 'carol@xample.com',
      },
    ],
    usernames: [
      { id: p('username_001'), username: 'alice', user_id: p('user_001') },
      { id: p('username_002'), username: 'bob', user_id: p('user_002') },
      { id: p('username_003'), username: 'carol', user_id: p('user_003') },
    ],
    links: [
      {
        id: p('link_001'),
        user_id: p('user_001'),
        url: 'https://example.com/1',
        alias: 'example-1',
        created_at: '2025-01-01T00:00:00Z',
      },
      {
        id: p('link_002'),
        user_id: p('user_002'),
        url: 'https://example.com/2',
        alias: 'example-2',
        created_at: '2025-01-02T00:00:00Z',
      },
      {
        id: p('link_003'),
        user_id: p('user_003'),
        url: 'https://example.com/3',
        alias: 'example-3',
        created_at: '2025-01-03T00:00:00Z',
      },
    ],
    transactions: [
      {
        id: p('tx_001'),
        user_id: p('user_001'),
        amount: 100,
        currency: 'USD',
        status: 'completed',
      },
      {
        id: p('tx_002'),
        user_id: p('user_002'),
        amount: 250.5,
        currency: 'EUR',
        status: 'pending',
      },
      {
        id: p('tx_003'),
        user_id: p('user_003'),
        amount: 33.33,
        currency: 'BTC',
        status: 'failed',
      },
    ],
    receipts: [
      {
        id: p('receipt_001'),
        transaction_id: p('tx_001'),
        url: 'https://receipts.example.com/1.pdf',
        created_at: '2025-01-01T00:00:00Z',
      },
      {
        id: p('receipt_002'),
        transaction_id: p('tx_002'),
        url: 'https://receipts.example.com/2.pdf',
        created_at: '2025-01-02T00:00:00Z',
      },
      {
        id: p('receipt_003'),
        transaction_id: p('tx_003'),
        url: 'https://receipts.example.com/3.pdf',
        created_at: '2025-01-03T00:00:00Z',
      },
    ],
  };
}