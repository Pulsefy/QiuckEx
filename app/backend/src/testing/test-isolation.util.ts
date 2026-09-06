import { randomUUID } from 'crypto';
import { SeedClient, seedDatabase, cleanDatabase } from './seed.util';

export interface TestIsolation {
  /** Seeds a fresh, uniquely-namespaced dataset and returns the prefix used. */
  seed(): Promise<string>;
  /** Removes the dataset created by `seed()`. */
  cleanup(): Promise<void>;
  /** Returns the current idPrefix, or empty string if no seed has run. */
  getPrefix(): string;
}

/**
 * Creates a per-test isolation helper. Call `seed()` in `beforeEach` and
 * `cleanup()` In `afterEach` to guarantee tests cannot observe each other's
 * records and that the database returns to a clean state afterwards.
 */
export function createTestIsolation(client: SeedClient): TestIsolation {
  let prefix = '';

  return {
    async seed(): Promise<string> {
      // Ensure a brand-new prefix each time (even if called twice).
      prefix = `test_${randomUUID().replace(/-/g, '')}`;
      await seedDatabase(client, { idPrefix: `${prefix}_` });
      return prefix;
    },

    async cleanup(): Promise<void> {
      if (prefix) {
        await cleanDatabase(client, `${prefix}_`);
        prefix = '';
      }
    },

    getPrefix(): string {
      return prefix;
    },
  };
}