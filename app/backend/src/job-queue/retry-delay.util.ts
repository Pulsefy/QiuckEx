/**
 * Job Queue System - Retry Delay Calculation Utility
 * 
 * Pure function for calculating retry delays based on retry policies.
 * Supports fixed, linear, and exponential backoff strategies with max delay caps.
 * 
 * **Validates: Requirements 3.2, 3.3**
 */

import { RetryPolicy } from './types';

/**
 * Calculate the retry delay in milliseconds based on retry policy and attempt count
 * 
 * This is a pure function that implements three backoff strategies:
 * - **fixed**: Always returns initialDelayMs
 * - **linear**: Returns initialDelayMs * attempts
 * - **exponential**: Returns initialDelayMs * 2^(attempts - 1)
 * 
 * All strategies enforce the maxDelayMs cap to prevent unbounded growth.
 * 
 * @param policy - The retry policy configuration
 * @param attempts - The current attempt count (1-indexed, first retry is attempt 1)
 * @returns The delay in milliseconds before the next retry
 * 
 * @example
 * // Fixed backoff: always 60 seconds
 * calculateRetryDelay({ backoffStrategy: 'fixed', initialDelayMs: 60000, maxDelayMs: 300000 }, 1) // 60000
 * calculateRetryDelay({ backoffStrategy: 'fixed', initialDelayMs: 60000, maxDelayMs: 300000 }, 5) // 60000
 * 
 * @example
 * // Linear backoff: grows linearly with attempts
 * calculateRetryDelay({ backoffStrategy: 'linear', initialDelayMs: 60000, maxDelayMs: 300000 }, 1) // 60000
 * calculateRetryDelay({ backoffStrategy: 'linear', initialDelayMs: 60000, maxDelayMs: 300000 }, 2) // 120000
 * calculateRetryDelay({ backoffStrategy: 'linear', initialDelayMs: 60000, maxDelayMs: 300000 }, 5) // 300000 (capped)
 * 
 * @example
 * // Exponential backoff: doubles with each attempt
 * calculateRetryDelay({ backoffStrategy: 'exponential', initialDelayMs: 1000, maxDelayMs: 60000 }, 1) // 1000
 * calculateRetryDelay({ backoffStrategy: 'exponential', initialDelayMs: 1000, maxDelayMs: 60000 }, 2) // 2000
 * calculateRetryDelay({ backoffStrategy: 'exponential', initialDelayMs: 1000, maxDelayMs: 60000 }, 6) // 32000
 * calculateRetryDelay({ backoffStrategy: 'exponential', initialDelayMs: 1000, maxDelayMs: 60000 }, 10) // 60000 (capped)
 * 
 * **Validates: Requirement 3.2** - Calculate next retry delay based on backoff strategy
 * **Validates: Requirement 3.3** - Enforce maxDelayMs cap
 */
export function calculateRetryDelay(
  policy: RetryPolicy,
  attempts: number,
): number {
  let delay: number;

  switch (policy.backoffStrategy) {
    case 'fixed':
      // Fixed backoff: always return the initial delay
      delay = policy.initialDelayMs;
      break;

    case 'linear':
      // Linear backoff: delay grows linearly with attempt count
      delay = policy.initialDelayMs * attempts;
      break;

    case 'exponential':
      // Exponential backoff: delay doubles with each attempt
      // Formula: initialDelayMs * 2^(attempts - 1)
      delay = policy.initialDelayMs * Math.pow(2, attempts - 1);
      break;

    default:
      // This should never happen with proper TypeScript typing
      throw new Error(
        `Unknown backoff strategy: ${(policy as RetryPolicy).backoffStrategy}`,
      );
  }

  // Enforce the maximum delay cap (Requirement 3.3)
  return Math.min(delay, policy.maxDelayMs);
}
