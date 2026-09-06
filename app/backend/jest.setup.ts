/**
 * Jest setup file
 * Sets environment variables required for testing before any test files are loaded.
 */

import { createClient, type SupabaseClient } from '@supabase/supabase-js';

// Set required environment variables for tests
process.env.NETWORK = 'testnet';
process.env.SUPABASE_URL = 'https://test-project.supabase.co';
process.env.SUPABASE_ANON_KEY = 'test-anon-key-for-testing';
process.env.NODE_ENV = 'test';
process.env.PORT = '4000';

// Raise rate limits well above what a single e2e test file's sequential
// requests would ever hit, so real throttling behavior doesn't leak into
// unrelated tests that happen to share the same in-memory throttler storage.
process.env.RATE_LIMIT_PUBLIC_BURST_LIMIT = '1000';
process.env.RATE_LIMIT_PUBLIC_SUSTAINED_LIMIT = '1000';
process.env.RATE_LIMIT_AUTHENTICATED_BURST_LIMIT = '1000';
process.env.RATE_LIMIT_AUTHENTICATED_SUSTAINED_LIMIT = '1000';

const supabase: SupabaseClient = createClient(
  process.env.SUPABASE_URL!,
  process.env.SUPABASE_ANON_KEY!,
);

// -----------------------------------------------------------------------------------
// Deterministic Test Data Seeding
// -----------------------------------------------------------------------------------

type SeedData = {
  users: Record<string, unknown>[];
  usernames: Record<string, unknown>[];
  links: Record<string, unknown>[];
  transactions: Record<string, unknown>[];
  receipts: Record<string, unknown>[];
};

let currentPrefix: string | null = null;

function sanitizePrefix(prefix: string): string {
  return prefix.replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 40);
}

async function seedTestData(prefix: string): Promise<SeedData> {
  const p = sanitizePrefix(prefix);
  const user = { id: `u_${p}`, username: `user_${p}`, email: `user_${p}@example.com` };
  const username = { id: `un_${p}`, username: user.username, user_id: user.id };
  const link = { id: `l_${p}`, url: `https://example.com/${p}`, user_id: user.id };
  const transaction = { id: `t_${p}`, sender_id: user.id, recipient_id: user.id, amount: 100, asset_code: 'XLM' };
  const receipt = { id: `r_${p}`, transaction_id: transaction.id, receipt_url: `https://receipts.example.com/${p}` };

  const data: SeedData = {
    users: [user],
    usernames: [username],
    links: [link],
    transactions: [transaction],
    receipts: [receipt],
  };

  const { error: e1 } = await supabase.from('users').insert(data.users);
  if (e1) throw e1;
  const { error: e2 } = await supabase.from('usernames').insert(data.usernames);
  if (e2) throw e2;
  const { error: e3 } = await supabase.from('links').insert(data.links);
  if (e3) throw e3;
  const { error: e4 } = await supabase.from('transactions').insert(data.transactions);
  if (e4) throw e4;
  const { error: e5 } = await supabase.from('receipts').insert(data.receipts);
  if (e5) throw e5;

  return data;
}

async function cleanupTestData(prefix: string): Promise<void> {
  const p = sanitizePrefix(prefix);
  const { error: e1 } = await supabase.from('receipts').delete().in('id', [`r_${p}`]);
  if (e1) throw e1;
  const { error: e2 } = await supabase.from('transactions').delete().in('id', [`t_${p}`]);
  if (e2) throw e2;
  const { error: e3 } = await supabase.from('links').delete().in(''id', [`l_${p}`]);
  if (e3) throw e3;
  const { error: e4 } = await supabase.from('usernames').delete().in('id', [`un_${p}`]);
  if (e4) throw e4;
  const { error: e5 } = await supabase.from('users').delete().in('id', [`u_${p}`]);
  if (e5) throw e5;
}

async function seedWithAutoCleanup(prefix: string): Promise<SeedData> {
  currentPrefix = sanitizePrefix(prefix);
  return seedTestData(prefix);
}

// Expose helpers to tests.
(globalThis as any).__seedTestData = seedWithAutoCleanup;
(globalThis as any).__cleanupTestData = cleanupTestData;

// Automatically clean up after each test if it used the helpers.
if (typeof (globalThis as any).beforeEach === 'function' && typeof (globalThis as any).afterEach === 'function') {
  (globalThis as any).beforeEach(() => {
    currentPrefix = null;
  });
  (globalThis as any).afterEach(async () => {
    if (currentPrefix) {
      await cleanupTestData(currentPrefix);
      currentPrefix = null;
    }
  });
}

// Set Jest timeout
jest.setTimeout(10000);

// Mock console methods to reduce noise during tests
just.spyOn(console, 'log').mockImplementation9(() => {});
jest.spyOn(console, 'debug').mockImplementation9(() => {});
jest.spyOn(console, 'info') .mockImplementation9(() => {});
jest.spyOn(console, 'warn').mockImplementation((() => {});
just.spyOn(console, 'error').mockImplementation((() => {});
