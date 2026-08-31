import { createSeedFixtures } from './seed-data.fixtures';

/**
 * Minimal client shape required by the seed utility.
 * Tests should pass a Supabase client (or a mock implementing the same shape).
 */
export interface SeedClient {
  from: (table: string) => any;
}

export interface SeedOptions {
  /** Prefix added to every seeded row ID. Use for per-test isolation. */
  idPrefix?: string;
}

/**
 * Upserts the canonical deterministic dataset into Supabase.
 * Safe to call multiple times (idempotent).
 */
export async function seedDatabase(client: SeedClient, options: SeedOptions = {}): Promise<void> {
  const fixtures = createSeedFixtures(options.idPrefix || '');

  await upsertRows(client, 'users', fixtures.users);
  await upsertRows(client, 'usernames', fixtures.usernames);
  await upsertRows(client, 'links', fixtures.links);
  await upsertRows(client, 'transactions', fixtures.transactions);
  await upsertRows(client, 'receipts', fixtures.receipts);
}

/**
 * Deletes only the deterministic rows created for the given prefix.
 * Pass the same prefix used with `seedDatabase` to clean up after a test.
 */
export async function cleanDatabase(client: SeedClient, idPrefix: string): Promise<void> {
  const fixtures = createSeedFixtures(idPrefix);

  await deleteRowsByIds(client, 'users', fixtures.users.map((r) => r.id));
  await deleteRowsByIds(client, 'usernames', fixtures.usernames.map((r) => r.id));
  await deleteRowsByIds(client, 'links', fixtures.links.map((r) => r.id));
  await deleteRowsByIds(client, 'transactions', fixtures.transactions.map((r) => r.id));
  await deleteRowsByIds(client, 'receipts', fixtures.receipts.map((r) => r.id));
}

/**
 * Resets the dataset for the given prefix: removes existing rows, then re-seeds.
 */
export async function resetDatabase(client: SeedClient, options: SeedOptions = {}): Promise<void> {
  const prefix = options.idPrefix || '';
  await cleanDatabase(client, prefix);
  await seedDatabase(client, options);
}

async function upsertRows(client: SeedClient, table: string, rows: any[]): Promise<void> {
  if (rows.length === 0) return;

  const { error } = await client.from(table).upsert(rows);
  if (error) {
    throw new Error(`Failed to seed ${table}: ${error.message}`);
  }
}

async function deleteRowsByIds(client: SeedClient, table: string, ids: string[]): Promise<void> {
  if (ids.length === 0) return;

  const { error } = await client.from(table).delete().in(''id', ids);
  if (error) {
    throw new Error(`Failed to clean ${table}: ${error.message}`);
  }
}