/**
 * Job Queue System - Job Registry Service
 * 
 * Maintains the mapping of job types to their handlers and retry policies.
 * Allows registration at application startup and retrieval during job execution.
 * 
 * **Validates: Requirements 1.3, 1.4**
 */

import { Injectable, Logger } from '@nestjs/common';
import { JobType, JobHandler, RetryPolicy } from './types';

/**
 * Registry service for job handlers and retry policies
 * 
 * This service maintains the mapping between job types and their:
 * - Handler implementations (execute, validate, onFailure)
 * - Retry policies (maxAttempts, backoff strategy, delays)
 * 
 * Handlers and policies are registered at application startup and
 * retrieved during job execution by the JobExecutor.
 */
@Injectable()
export class JobRegistry {
  private readonly logger = new Logger(JobRegistry.name);
  
  /**
   * Map of job types to their handler implementations
   */
  private readonly handlers = new Map<JobType, JobHandler>();
  
  /**
   * Map of job types to their retry policies
   */
  private readonly policies = new Map<JobType, RetryPolicy>();

  /**
   * Register a job handler with its retry policy
   * 
   * @param type - Job type to register
   * @param handler - Handler implementation for this job type
   * @param policy - Retry policy configuration for this job type
   * 
   * **Validates: Requirement 1.3** - Support registering Job_Type handlers at application startup
   */
  registerHandler(
    type: JobType,
    handler: JobHandler,
    policy: RetryPolicy,
  ): void {
    if (this.handlers.has(type)) {
      this.logger.warn(`Overwriting existing handler for job type: ${type}`);
    }

    this.handlers.set(type, handler);
    this.policies.set(type, policy);

    this.logger.log(
      `Registered handler for job type: ${type} ` +
      `(maxAttempts: ${policy.maxAttempts}, backoff: ${policy.backoffStrategy})`,
    );
  }

  /**
   * Get the handler for a specific job type
   * 
   * @param type - Job type
   * @returns The registered handler
   * @throws Error if no handler is registered for this type
   * 
   * **Validates: Requirement 1.4** - Validate that a corresponding Job_Handler exists
   */
  getHandler(type: JobType): JobHandler {
    const handler = this.handlers.get(type);
    
    if (!handler) {
      throw new Error(`No handler registered for job type: ${type}`);
    }

    return handler;
  }

  /**
   * Get the retry policy for a specific job type
   * 
   * @param type - Job type
   * @returns The registered retry policy
   * @throws Error if no policy is registered for this type
   */
  getPolicy(type: JobType): RetryPolicy {
    const policy = this.policies.get(type);
    
    if (!policy) {
      throw new Error(`No retry policy registered for job type: ${type}`);
    }

    return policy;
  }

  /**
   * Check if a job type is registered
   * 
   * @param type - Job type to check
   * @returns True if the job type has a registered handler and policy
   * 
   * **Validates: Requirement 1.4** - Validate that a corresponding Job_Handler exists
   */
  isRegistered(type: JobType): boolean {
    return this.handlers.has(type) && this.policies.has(type);
  }

  /**
   * Get all registered job types
   * 
   * @returns Array of registered job types
   */
  getRegisteredTypes(): JobType[] {
    return Array.from(this.handlers.keys());
  }

  /**
   * Clear all registered handlers and policies
   * 
   * Primarily used for testing purposes
   */
  clear(): void {
    this.handlers.clear();
    this.policies.clear();
    this.logger.debug('Cleared all registered handlers and policies');
  }
}
