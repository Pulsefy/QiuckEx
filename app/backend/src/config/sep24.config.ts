/**
 * SEP-24 polling configuration.
 *
 * All values have sensible defaults; override via environment variables.
 */

import { registerAs } from '@nestjs/config';

export const sep24Config = registerAs('sep24', () => ({
  /**
   * Age (ms) after which a still-pending transaction is flagged as stuck.
   * Default: 1 hour.
   */
  stuckThresholdMs: parseInt(
    process.env['SEP24_STUCK_THRESHOLD_MS'] ?? String(60 * 60 * 1000),
    10,
  ),

  /**
   * Maximum consecutive poll failures before a transaction is excluded from
   * further polling.
   * Default: 5.
   */
  maxPollFailures: parseInt(
    process.env['SEP24_MAX_POLL_FAILURES'] ?? '5',
    10,
  ),

  /**
   * Maximum transactions processed per poll cycle.
   * Default: 50.
   */
  batchSize: parseInt(
    process.env['SEP24_POLL_BATCH_SIZE'] ?? '50',
    10,
  ),
}));
