/**
 * Job Registry Service - Unit Tests
 * 
 * Tests for the JobRegistry service that manages job type handlers and retry policies.
 * 
 * **Validates: Requirements 1.3, 1.4**
 */

import { Test, TestingModule } from '@nestjs/testing';
import { JobRegistry } from './job-registry.service';
import { JobType, JobHandler, RetryPolicy, Job, CancellationToken } from './types';

describe('JobRegistry', () => {
  let registry: JobRegistry;

  // Mock handler implementation
  const mockHandler: JobHandler = {
    execute: jest.fn(),
    validate: jest.fn(),
    onFailure: jest.fn(),
  };

  // Mock retry policy
  const mockPolicy: RetryPolicy = {
    maxAttempts: 5,
    backoffStrategy: 'exponential',
    initialDelayMs: 60000,
    maxDelayMs: 7200000,
    visibilityTimeoutMs: 300000,
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [JobRegistry],
    }).compile();

    registry = module.get<JobRegistry>(JobRegistry);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('registerHandler', () => {
    it('should register a handler with its retry policy', () => {
      // Act
      registry.registerHandler(JobType.WEBHOOK_DELIVERY, mockHandler, mockPolicy);

      // Assert
      expect(registry.isRegistered(JobType.WEBHOOK_DELIVERY)).toBe(true);
      expect(registry.getHandler(JobType.WEBHOOK_DELIVERY)).toBe(mockHandler);
      expect(registry.getPolicy(JobType.WEBHOOK_DELIVERY)).toBe(mockPolicy);
    });

    it('should allow overwriting an existing handler', () => {
      // Arrange
      const newHandler: JobHandler = {
        execute: jest.fn(),
        validate: jest.fn(),
        onFailure: jest.fn(),
      };
      const newPolicy: RetryPolicy = {
        maxAttempts: 3,
        backoffStrategy: 'linear',
        initialDelayMs: 30000,
        maxDelayMs: 3600000,
        visibilityTimeoutMs: 600000,
      };

      // Act
      registry.registerHandler(JobType.WEBHOOK_DELIVERY, mockHandler, mockPolicy);
      registry.registerHandler(JobType.WEBHOOK_DELIVERY, newHandler, newPolicy);

      // Assert
      expect(registry.getHandler(JobType.WEBHOOK_DELIVERY)).toBe(newHandler);
      expect(registry.getPolicy(JobType.WEBHOOK_DELIVERY)).toBe(newPolicy);
    });

    it('should register multiple job types independently', () => {
      // Arrange
      const handler1: JobHandler = {
        execute: jest.fn(),
        validate: jest.fn(),
        onFailure: jest.fn(),
      };
      const handler2: JobHandler = {
        execute: jest.fn(),
        validate: jest.fn(),
        onFailure: jest.fn(),
      };
      const policy1: RetryPolicy = {
        maxAttempts: 5,
        backoffStrategy: 'exponential',
        initialDelayMs: 60000,
        maxDelayMs: 7200000,
        visibilityTimeoutMs: 300000,
      };
      const policy2: RetryPolicy = {
        maxAttempts: 3,
        backoffStrategy: 'linear',
        initialDelayMs: 30000,
        maxDelayMs: 3600000,
        visibilityTimeoutMs: 600000,
      };

      // Act
      registry.registerHandler(JobType.WEBHOOK_DELIVERY, handler1, policy1);
      registry.registerHandler(JobType.RECURRING_PAYMENT, handler2, policy2);

      // Assert
      expect(registry.isRegistered(JobType.WEBHOOK_DELIVERY)).toBe(true);
      expect(registry.isRegistered(JobType.RECURRING_PAYMENT)).toBe(true);
      expect(registry.getHandler(JobType.WEBHOOK_DELIVERY)).toBe(handler1);
      expect(registry.getHandler(JobType.RECURRING_PAYMENT)).toBe(handler2);
      expect(registry.getPolicy(JobType.WEBHOOK_DELIVERY)).toBe(policy1);
      expect(registry.getPolicy(JobType.RECURRING_PAYMENT)).toBe(policy2);
    });
  });

  describe('getHandler', () => {
    it('should return the registered handler for a job type', () => {
      // Arrange
      registry.registerHandler(JobType.WEBHOOK_DELIVERY, mockHandler, mockPolicy);

      // Act
      const handler = registry.getHandler(JobType.WEBHOOK_DELIVERY);

      // Assert
      expect(handler).toBe(mockHandler);
    });

    it('should throw an error for unregistered job type', () => {
      // Act & Assert
      expect(() => registry.getHandler(JobType.WEBHOOK_DELIVERY)).toThrow(
        'No handler registered for job type: webhook_delivery',
      );
    });
  });

  describe('getPolicy', () => {
    it('should return the registered retry policy for a job type', () => {
      // Arrange
      registry.registerHandler(JobType.WEBHOOK_DELIVERY, mockHandler, mockPolicy);

      // Act
      const policy = registry.getPolicy(JobType.WEBHOOK_DELIVERY);

      // Assert
      expect(policy).toBe(mockPolicy);
    });

    it('should throw an error for unregistered job type', () => {
      // Act & Assert
      expect(() => registry.getPolicy(JobType.WEBHOOK_DELIVERY)).toThrow(
        'No retry policy registered for job type: webhook_delivery',
      );
    });
  });

  describe('isRegistered', () => {
    it('should return true for registered job type', () => {
      // Arrange
      registry.registerHandler(JobType.WEBHOOK_DELIVERY, mockHandler, mockPolicy);

      // Act & Assert
      expect(registry.isRegistered(JobType.WEBHOOK_DELIVERY)).toBe(true);
    });

    it('should return false for unregistered job type', () => {
      // Act & Assert
      expect(registry.isRegistered(JobType.WEBHOOK_DELIVERY)).toBe(false);
    });

    it('should return false after clearing registry', () => {
      // Arrange
      registry.registerHandler(JobType.WEBHOOK_DELIVERY, mockHandler, mockPolicy);

      // Act
      registry.clear();

      // Assert
      expect(registry.isRegistered(JobType.WEBHOOK_DELIVERY)).toBe(false);
    });
  });

  describe('getRegisteredTypes', () => {
    it('should return empty array when no types are registered', () => {
      // Act
      const types = registry.getRegisteredTypes();

      // Assert
      expect(types).toEqual([]);
    });

    it('should return all registered job types', () => {
      // Arrange
      const handler1: JobHandler = {
        execute: jest.fn(),
        validate: jest.fn(),
        onFailure: jest.fn(),
      };
      const handler2: JobHandler = {
        execute: jest.fn(),
        validate: jest.fn(),
        onFailure: jest.fn(),
      };
      const policy: RetryPolicy = {
        maxAttempts: 5,
        backoffStrategy: 'exponential',
        initialDelayMs: 60000,
        maxDelayMs: 7200000,
        visibilityTimeoutMs: 300000,
      };

      registry.registerHandler(JobType.WEBHOOK_DELIVERY, handler1, policy);
      registry.registerHandler(JobType.RECURRING_PAYMENT, handler2, policy);

      // Act
      const types = registry.getRegisteredTypes();

      // Assert
      expect(types).toHaveLength(2);
      expect(types).toContain(JobType.WEBHOOK_DELIVERY);
      expect(types).toContain(JobType.RECURRING_PAYMENT);
    });
  });

  describe('clear', () => {
    it('should remove all registered handlers and policies', () => {
      // Arrange
      registry.registerHandler(JobType.WEBHOOK_DELIVERY, mockHandler, mockPolicy);
      registry.registerHandler(JobType.RECURRING_PAYMENT, mockHandler, mockPolicy);

      // Act
      registry.clear();

      // Assert
      expect(registry.getRegisteredTypes()).toEqual([]);
      expect(registry.isRegistered(JobType.WEBHOOK_DELIVERY)).toBe(false);
      expect(registry.isRegistered(JobType.RECURRING_PAYMENT)).toBe(false);
    });
  });
});
