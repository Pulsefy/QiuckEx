/**
 * Unit tests for retry delay calculation utility
 * 
 * Tests the calculateRetryDelay function with all backoff strategies
 * and verifies maxDelayMs cap enforcement.
 */

import { calculateRetryDelay } from './retry-delay.util';
import { RetryPolicy } from './types';

describe('calculateRetryDelay', () => {
  describe('fixed backoff strategy', () => {
    it('should return initialDelayMs for all attempts', () => {
      const policy: RetryPolicy = {
        maxAttempts: 5,
        backoffStrategy: 'fixed',
        initialDelayMs: 60000,
        maxDelayMs: 300000,
        visibilityTimeoutMs: 300000,
      };

      expect(calculateRetryDelay(policy, 1)).toBe(60000);
      expect(calculateRetryDelay(policy, 2)).toBe(60000);
      expect(calculateRetryDelay(policy, 5)).toBe(60000);
      expect(calculateRetryDelay(policy, 10)).toBe(60000);
    });

    it('should enforce maxDelayMs cap even for fixed strategy', () => {
      const policy: RetryPolicy = {
        maxAttempts: 5,
        backoffStrategy: 'fixed',
        initialDelayMs: 100000,
        maxDelayMs: 50000, // Max is less than initial
        visibilityTimeoutMs: 300000,
      };

      expect(calculateRetryDelay(policy, 1)).toBe(50000);
      expect(calculateRetryDelay(policy, 5)).toBe(50000);
    });
  });

  describe('linear backoff strategy', () => {
    it('should grow linearly with attempt count', () => {
      const policy: RetryPolicy = {
        maxAttempts: 5,
        backoffStrategy: 'linear',
        initialDelayMs: 60000,
        maxDelayMs: 500000,
        visibilityTimeoutMs: 300000,
      };

      expect(calculateRetryDelay(policy, 1)).toBe(60000); // 60000 * 1
      expect(calculateRetryDelay(policy, 2)).toBe(120000); // 60000 * 2
      expect(calculateRetryDelay(policy, 3)).toBe(180000); // 60000 * 3
      expect(calculateRetryDelay(policy, 5)).toBe(300000); // 60000 * 5
    });

    it('should enforce maxDelayMs cap', () => {
      const policy: RetryPolicy = {
        maxAttempts: 10,
        backoffStrategy: 'linear',
        initialDelayMs: 60000,
        maxDelayMs: 300000,
        visibilityTimeoutMs: 300000,
      };

      expect(calculateRetryDelay(policy, 4)).toBe(240000); // 60000 * 4 = 240000 (under cap)
      expect(calculateRetryDelay(policy, 5)).toBe(300000); // 60000 * 5 = 300000 (at cap)
      expect(calculateRetryDelay(policy, 6)).toBe(300000); // 60000 * 6 = 360000 (capped to 300000)
      expect(calculateRetryDelay(policy, 10)).toBe(300000); // 60000 * 10 = 600000 (capped to 300000)
    });
  });

  describe('exponential backoff strategy', () => {
    it('should double with each attempt', () => {
      const policy: RetryPolicy = {
        maxAttempts: 10,
        backoffStrategy: 'exponential',
        initialDelayMs: 1000,
        maxDelayMs: 100000,
        visibilityTimeoutMs: 300000,
      };

      expect(calculateRetryDelay(policy, 1)).toBe(1000); // 1000 * 2^0 = 1000
      expect(calculateRetryDelay(policy, 2)).toBe(2000); // 1000 * 2^1 = 2000
      expect(calculateRetryDelay(policy, 3)).toBe(4000); // 1000 * 2^2 = 4000
      expect(calculateRetryDelay(policy, 4)).toBe(8000); // 1000 * 2^3 = 8000
      expect(calculateRetryDelay(policy, 5)).toBe(16000); // 1000 * 2^4 = 16000
      expect(calculateRetryDelay(policy, 6)).toBe(32000); // 1000 * 2^5 = 32000
    });

    it('should enforce maxDelayMs cap', () => {
      const policy: RetryPolicy = {
        maxAttempts: 10,
        backoffStrategy: 'exponential',
        initialDelayMs: 1000,
        maxDelayMs: 60000,
        visibilityTimeoutMs: 300000,
      };

      expect(calculateRetryDelay(policy, 6)).toBe(32000); // 1000 * 2^5 = 32000 (under cap)
      expect(calculateRetryDelay(policy, 7)).toBe(60000); // 1000 * 2^6 = 64000 (capped to 60000)
      expect(calculateRetryDelay(policy, 10)).toBe(60000); // 1000 * 2^9 = 512000 (capped to 60000)
    });

    it('should handle webhook delivery policy from design', () => {
      // From design: webhook_delivery uses exponential backoff
      // maxAttempts=5, initialDelayMs=60000, maxDelayMs=7200000 (2 hours)
      const policy: RetryPolicy = {
        maxAttempts: 5,
        backoffStrategy: 'exponential',
        initialDelayMs: 60000,
        maxDelayMs: 7200000,
        visibilityTimeoutMs: 300000,
      };

      expect(calculateRetryDelay(policy, 1)).toBe(60000); // 60s
      expect(calculateRetryDelay(policy, 2)).toBe(120000); // 2min
      expect(calculateRetryDelay(policy, 3)).toBe(240000); // 4min
      expect(calculateRetryDelay(policy, 4)).toBe(480000); // 8min
      expect(calculateRetryDelay(policy, 5)).toBe(960000); // 16min
    });

    it('should handle stellar reconnect policy from design', () => {
      // From design: stellar_reconnect uses exponential backoff
      // maxAttempts=0 (unlimited), initialDelayMs=1000, maxDelayMs=60000
      const policy: RetryPolicy = {
        maxAttempts: 0,
        backoffStrategy: 'exponential',
        initialDelayMs: 1000,
        maxDelayMs: 60000,
        visibilityTimeoutMs: 120000,
      };

      expect(calculateRetryDelay(policy, 1)).toBe(1000); // 1s
      expect(calculateRetryDelay(policy, 2)).toBe(2000); // 2s
      expect(calculateRetryDelay(policy, 3)).toBe(4000); // 4s
      expect(calculateRetryDelay(policy, 4)).toBe(8000); // 8s
      expect(calculateRetryDelay(policy, 5)).toBe(16000); // 16s
      expect(calculateRetryDelay(policy, 6)).toBe(32000); // 32s
      expect(calculateRetryDelay(policy, 7)).toBe(60000); // 64s capped to 60s
      expect(calculateRetryDelay(policy, 10)).toBe(60000); // Capped at 60s
    });
  });

  describe('edge cases', () => {
    it('should handle attempt count of 0', () => {
      const policy: RetryPolicy = {
        maxAttempts: 5,
        backoffStrategy: 'exponential',
        initialDelayMs: 1000,
        maxDelayMs: 60000,
        visibilityTimeoutMs: 300000,
      };

      // 2^(0-1) = 2^-1 = 0.5, so 1000 * 0.5 = 500
      expect(calculateRetryDelay(policy, 0)).toBe(500);
    });

    it('should handle very large attempt counts', () => {
      const policy: RetryPolicy = {
        maxAttempts: 100,
        backoffStrategy: 'exponential',
        initialDelayMs: 1000,
        maxDelayMs: 60000,
        visibilityTimeoutMs: 300000,
      };

      // Should be capped at maxDelayMs
      expect(calculateRetryDelay(policy, 100)).toBe(60000);
      expect(calculateRetryDelay(policy, 1000)).toBe(60000);
    });

    it('should handle initialDelayMs of 0', () => {
      const policy: RetryPolicy = {
        maxAttempts: 5,
        backoffStrategy: 'exponential',
        initialDelayMs: 0,
        maxDelayMs: 60000,
        visibilityTimeoutMs: 300000,
      };

      expect(calculateRetryDelay(policy, 1)).toBe(0);
      expect(calculateRetryDelay(policy, 5)).toBe(0);
    });

    it('should handle maxDelayMs of 0', () => {
      const policy: RetryPolicy = {
        maxAttempts: 5,
        backoffStrategy: 'exponential',
        initialDelayMs: 1000,
        maxDelayMs: 0,
        visibilityTimeoutMs: 300000,
      };

      // All delays should be capped to 0
      expect(calculateRetryDelay(policy, 1)).toBe(0);
      expect(calculateRetryDelay(policy, 5)).toBe(0);
    });
  });

  describe('requirement validation', () => {
    it('should validate Requirement 3.2: Calculate retry delay based on backoff strategy', () => {
      const fixedPolicy: RetryPolicy = {
        maxAttempts: 5,
        backoffStrategy: 'fixed',
        initialDelayMs: 60000,
        maxDelayMs: 300000,
        visibilityTimeoutMs: 300000,
      };

      const linearPolicy: RetryPolicy = {
        maxAttempts: 5,
        backoffStrategy: 'linear',
        initialDelayMs: 60000,
        maxDelayMs: 300000,
        visibilityTimeoutMs: 300000,
      };

      const exponentialPolicy: RetryPolicy = {
        maxAttempts: 5,
        backoffStrategy: 'exponential',
        initialDelayMs: 60000,
        maxDelayMs: 300000,
        visibilityTimeoutMs: 300000,
      };

      // All three strategies should produce different results for attempt 3
      const fixedDelay = calculateRetryDelay(fixedPolicy, 3);
      const linearDelay = calculateRetryDelay(linearPolicy, 3);
      const exponentialDelay = calculateRetryDelay(exponentialPolicy, 3);

      expect(fixedDelay).toBe(60000); // Always 60s
      expect(linearDelay).toBe(180000); // 60s * 3 = 180s
      expect(exponentialDelay).toBe(240000); // 60s * 2^2 = 240s

      // Verify they're all different
      expect(fixedDelay).not.toBe(linearDelay);
      expect(linearDelay).not.toBe(exponentialDelay);
      expect(fixedDelay).not.toBe(exponentialDelay);
    });

    it('should validate Requirement 3.3: Enforce maxDelayMs cap', () => {
      const policy: RetryPolicy = {
        maxAttempts: 10,
        backoffStrategy: 'exponential',
        initialDelayMs: 1000,
        maxDelayMs: 10000,
        visibilityTimeoutMs: 300000,
      };

      // Test multiple attempts that would exceed the cap
      for (let attempt = 1; attempt <= 20; attempt++) {
        const delay = calculateRetryDelay(policy, attempt);
        
        // Delay should NEVER exceed maxDelayMs
        expect(delay).toBeLessThanOrEqual(policy.maxDelayMs);
      }
    });
  });
});
