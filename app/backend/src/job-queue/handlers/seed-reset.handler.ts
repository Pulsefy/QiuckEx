/**
 * Job Queue System - Seed Reset Handler
 * 
 * Handles seed reset jobs triggered by the scheduler.
 * Implements retry logic and failure handling.
 */

import { Injectable, Logger } from '@nestjs/common';
import { Job, JobHandler } from '../types';
import { DemoService } from '../../demos/demo.service';
import { SeedResetScheduler } from '../../demos/seed-reset.scheduler';

export interface SeedResetPayload {
  trigger: 'scheduled' | 'manual' | 'retry' | 'force';
  options?: {
    force?: boolean;
    excludeTables?: string[];
    preserveOptions?: Record<string, unknown>;
  };
  attempt: number;
  maxRetries: number;
}

export interface SeedResetResult {
  success: boolean;
  seededLinks: number;
  seededTransactions: number;
  errors: string[];
  executionTimeMs: number;
}

/**
 * Error thrown when a seed reset fails permanently
 */
export class PermanentSeedResetError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PermanentSeedResetError';
  }
}

@Injectable()
export class SeedResetHandler implements JobHandler<SeedResetPayload> {
  private readonly logger = new Logger(SeedResetHandler.name);

  constructor(
    private readonly demoService: DemoService,
    private readonly scheduler: SeedResetScheduler,
  ) {}

  /**
   * Validate job payload
   * Called before enqueueing to ensure payload is valid
   */
  async validate(payload: unknown): Promise<void> {
    const typed = payload as SeedResetPayload;
    if (!typed) {
      throw new Error('Payload is required');
    }

    if (!typed.trigger) {
      throw new Error('Trigger is required');
    }

    if (typed.attempt === undefined || typed.attempt < 0) {
      throw new Error('Attempt must be a non-negative number');
    }

    if (typed.maxRetries === undefined || typed.maxRetries < 0) {
      throw new Error('Max retries must be a non-negative number');
    }

    if (typed.attempt > typed.maxRetries) {
      throw new Error('Attempt cannot exceed max retries');
    }
  }

  /**
   * Handle seed reset job
   */
  async handle(job: Job<SeedResetPayload>): Promise<SeedResetResult> {
    const startTime = Date.now();
    const { trigger, options, attempt, maxRetries } = job.payload;

    this.logger.log(
      `Processing seed reset job ${job.id} (trigger: ${trigger}, attempt: ${attempt + 1}/${maxRetries + 1})`,
    );

    try {
      // Step 1: Check if reset should run based on exclusions
      const status = this.scheduler.getStatus();
      if (!status.enabled && trigger !== 'force') {
        throw new PermanentSeedResetError(
          'Seed reset is disabled. Use force trigger to override.',
        );
      }

      // Step 2: Check if we're on testnet
      try {
        await this.demoService.status();
      } catch (error) {
        throw new PermanentSeedResetError(
          `Demo service unavailable: ${(error as Error).message}`,
        );
      }

      // Step 3: Execute the reset
      let result: SeedResetResult;

      if (trigger === 'force' || options?.force) {
        result = await this.executeForceReset();
      } else {
        result = await this.executeReset();
      }

      // Step 4: Log success
      this.logger.log(
        `Seed reset job ${job.id} completed successfully in ${result.executionTimeMs}ms`,
      );

      return {
        ...result,
        executionTimeMs: Date.now() - startTime,
      };

    } catch (error) {
      const errorMsg = `Seed reset job ${job.id} failed: ${(error as Error).message}`;
      this.logger.error(errorMsg);

      // Check if this is a permanent error
      if (error instanceof PermanentSeedResetError) {
        throw error;
      }

      // Re-throw for retry
      throw error;
    }
  }

  /**
   * Execute normal reset
   */
  private async executeReset(): Promise<SeedResetResult> {
    const errors: string[] = [];
    let seededLinks = 0;
    let seededTransactions = 0;

    try {
      // Clear existing data
      const clearResult = await this.demoService.clear();
      this.logger.debug(
        `Cleared ${clearResult.deletedLinks} links and ${clearResult.deletedTransactions} transactions`,
      );
    } catch (error) {
      const errorMsg = `Clear failed: ${(error as Error).message}`;
      this.logger.error(errorMsg);
      errors.push(errorMsg);
    }

    try {
      // Seed new data
      const seedResult = await this.demoService.seed();
      seededLinks = seedResult.seededLinks;
      seededTransactions = seedResult.seededTransactions;

      this.logger.debug(
        `Seeded ${seededLinks} links and ${seededTransactions} transactions`,
      );
    } catch (error) {
      const errorMsg = `Seed failed: ${(error as Error).message}`;
      this.logger.error(errorMsg);
      errors.push(errorMsg);
    }

    return {
      success: errors.length === 0,
      seededLinks,
      seededTransactions,
      errors,
      executionTimeMs: 0,
    };
  }

  /**
   * Execute force reset (bypasses exclusions)
   */
  private async executeForceReset(): Promise<SeedResetResult> {
    this.logger.warn('Executing force reset - bypassing exclusions');
    return this.executeReset();
  }

  /**
   * Get maximum number of attempts for this job type
   */
  getMaxAttempts(): number {
    return 3; // 3 attempts total (1 initial + 2 retries)
  }

  /**
   * Get retry delay in milliseconds
   */
  getRetryDelay(): number {
    return 60000; // 60 seconds
  }
}