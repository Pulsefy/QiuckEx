/**
 * Job Queue System - Module Definition
 * 
 * Provides the unified job queue system for background processing.
 * Exports services for use by other modules.
 */

import { Module, forwardRef } from '@nestjs/common';
import { JobQueueService } from './job-queue.service';
import { JobRepository } from './job.repository';
import { JobRegistry } from './job-registry.service';
import { JobExecutor } from './job-executor.service';
import { CancellationStore } from './cancellation-token';
import { JobQueueInitializer } from './job-queue-initializer.service';
import { JobAdminController } from './job-admin.controller';
import { JobQueueMetricsService } from './job-queue-metrics.service';
import { SupabaseModule } from '../supabase/supabase.module';
import { NotificationsModule } from '../notifications/notifications.module';
import { LinksModule } from '../links/links.module';
import { ReconciliationModule } from '../reconciliation/reconciliation.module';
import { IngestionModule } from '../ingestion/ingestion.module';
import { AuthModule } from '../auth/auth.module';
import { MetricsModule } from '../metrics/metrics.module';
import { 
  WebhookDeliveryHandler, 
  RecurringPaymentHandler, 
  ExportGenerationHandler,
  ReconciliationHandler,
  StellarReconnectHandler,
} from './handlers';

/**
 * Job Queue Module
 * 
 * Provides:
 * - JobQueueService: Public API for enqueuing and managing jobs
 * - JobExecutor: Background polling service for job execution
 * - JobRegistry: Registry for job handlers and retry policies
 * - JobRepository: Database access layer
 * - CancellationStore: Cancellation token management
 * - JobQueueInitializer: Registers all job handlers at startup
 * - JobQueueMetricsService: Prometheus metrics for job lifecycle events
 * - JobAdminController: Admin API endpoints for job monitoring and management
 * - WebhookDeliveryHandler: Handler for webhook delivery jobs
 * - RecurringPaymentHandler: Handler for recurring payment jobs
 * - ExportGenerationHandler: Handler for export generation jobs
 * - ReconciliationHandler: Handler for reconciliation jobs
 * - StellarReconnectHandler: Handler for Stellar SSE reconnection jobs
 */
@Module({
  imports: [
    SupabaseModule,
    AuthModule,
    MetricsModule,
    forwardRef(() => NotificationsModule),
    forwardRef(() => LinksModule),
    forwardRef(() => ReconciliationModule),
    forwardRef(() => IngestionModule),
  ],
  controllers: [
    JobAdminController,
  ],
  providers: [
    JobQueueService,
    JobRepository,
    JobRegistry,
    JobExecutor,
    CancellationStore,
    JobQueueInitializer,
    JobQueueMetricsService,
    WebhookDeliveryHandler,
    RecurringPaymentHandler,
    ExportGenerationHandler,
    ReconciliationHandler,
    StellarReconnectHandler,
  ],
  exports: [
    JobQueueService,
    JobRegistry,
    JobRepository,
    JobQueueMetricsService,
    WebhookDeliveryHandler,
    RecurringPaymentHandler,
    ExportGenerationHandler,
    ReconciliationHandler,
    StellarReconnectHandler,
  ],
})
export class JobQueueModule {}
