/**
 * Job Queue System - Initializer Service
 * 
 * Registers all job handlers with their retry policies at application startup.
 * This service implements OnModuleInit to ensure handlers are registered
 * before the JobExecutor starts processing jobs.
 * 
 * Requirements: 1.3, 7.1
 */

import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { JobRegistry } from './job-registry.service';
import { JobType } from './types';
import { 
  WebhookDeliveryHandler, 
  RecurringPaymentHandler, 
  ExportGenerationHandler,
  ReconciliationHandler,
  StellarReconnectHandler,
} from './handlers';

/**
 * Job Queue Initializer Service
 * 
 * Responsible for registering all job handlers with their retry policies
 * at application startup. This ensures the JobRegistry is fully populated
 * before the JobExecutor begins polling for jobs.
 */
@Injectable()
export class JobQueueInitializer implements OnModuleInit {
  private readonly logger = new Logger(JobQueueInitializer.name);

  constructor(
    private readonly registry: JobRegistry,
    private readonly webhookDeliveryHandler: WebhookDeliveryHandler,
    private readonly recurringPaymentHandler: RecurringPaymentHandler,
    private readonly exportGenerationHandler: ExportGenerationHandler,
    private readonly reconciliationHandler: ReconciliationHandler,
    private readonly stellarReconnectHandler: StellarReconnectHandler,
  ) {}

  /**
   * Register all job handlers on module initialization
   * 
   * This method is called by NestJS after the module's dependencies are resolved
   * but before the application starts accepting requests.
   * 
   * **Validates: Requirements 1.3, 7.1, 8.1, 9.1, 10.1, 11.1**
   */
  async onModuleInit(): Promise<void> {
    this.logger.log('Registering job handlers...');

    // Register webhook_delivery handler
    // Requirements: 7.1
    this.registry.registerHandler(
      JobType.WEBHOOK_DELIVERY,
      this.webhookDeliveryHandler,
      {
        maxAttempts: 5,
        backoffStrategy: 'exponential',
        initialDelayMs: 60000,        // 1 minute
        maxDelayMs: 7200000,          // 2 hours
        visibilityTimeoutMs: 300000,  // 5 minutes
      },
    );

    // Register recurring_payment handler
    // Requirements: 8.1
    this.registry.registerHandler(
      JobType.RECURRING_PAYMENT,
      this.recurringPaymentHandler,
      {
        maxAttempts: 3,
        backoffStrategy: 'exponential',
        initialDelayMs: 60000,        // 1 minute
        maxDelayMs: 3600000,          // 1 hour
        visibilityTimeoutMs: 600000,  // 10 minutes
      },
    );

    // Register export_generation handler
    // Requirements: 9.1
    this.registry.registerHandler(
      JobType.EXPORT_GENERATION,
      this.exportGenerationHandler,
      {
        maxAttempts: 2,
        backoffStrategy: 'fixed',
        initialDelayMs: 300000,       // 5 minutes
        maxDelayMs: 300000,           // 5 minutes (fixed strategy)
        visibilityTimeoutMs: 600000,  // 10 minutes
      },
    );

    // Register reconciliation handler
    // Requirements: 10.1
    this.registry.registerHandler(
      JobType.RECONCILIATION,
      this.reconciliationHandler,
      {
        maxAttempts: 1,
        backoffStrategy: 'fixed',
        initialDelayMs: 0,            // No delay (immediate retry if needed)
        maxDelayMs: 0,                // No delay (fixed strategy)
        visibilityTimeoutMs: 300000,  // 5 minutes
      },
    );

    // Register stellar_reconnect handler
    // Requirements: 11.1
    this.registry.registerHandler(
      JobType.STELLAR_RECONNECT,
      this.stellarReconnectHandler,
      {
        maxAttempts: 0,               // Unlimited retries
        backoffStrategy: 'exponential',
        initialDelayMs: 1000,         // 1 second
        maxDelayMs: 60000,            // 1 minute
        visibilityTimeoutMs: 120000,  // 2 minutes
      },
    );

    this.logger.log('Job handler registration complete');
  }
}
