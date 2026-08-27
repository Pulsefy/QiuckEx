/**
 * Job Queue Metrics Service - Unit Tests
 *
 * Uses a real prom-client registry (via MetricsService) so assertions verify
 * actual metric names, labels, and values as they would appear on /metrics.
 */

import { Test, TestingModule } from '@nestjs/testing';
import { JobQueueMetricsService } from './job-queue-metrics.service';
import { MetricsService } from '../metrics/metrics.service';
import { JobType } from './types';

describe('JobQueueMetricsService', () => {
  let service: JobQueueMetricsService;
  let metricsService: MetricsService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [JobQueueMetricsService, MetricsService],
    }).compile();

    metricsService = module.get(MetricsService);
    metricsService.onModuleInit();

    service = module.get(JobQueueMetricsService);
    service.onModuleInit();
  });

  it('should emit jobs_retried_total on retry', async () => {
    service.incrementJobsRetried(JobType.WEBHOOK_DELIVERY);

    const output = await metricsService.getRegistry().metrics();

    expect(output).toContain('jobs_retried_total');
    expect(output).toMatch(
      /jobs_retried_total\{type="webhook_delivery"\} 1/,
    );
  });

  it('should emit jobs_dlq_oldest_age_seconds and jobs_dlq_alert_active on dead-letter', async () => {
    service.setDlqOldestAgeSeconds(JobType.WEBHOOK_DELIVERY, 4200);
    service.setDlqAlertActive(JobType.WEBHOOK_DELIVERY, 'age', true);

    const output = await metricsService.getRegistry().metrics();

    expect(output).toMatch(
      /jobs_dlq_oldest_age_seconds\{type="webhook_delivery"\} 4200/,
    );
    expect(output).toMatch(
      /jobs_dlq_alert_active\{type="webhook_delivery",reason="age"\} 1/,
    );
  });

  it('should emit jobs_completed_total on job success', async () => {
    service.incrementJobsCompleted(JobType.WEBHOOK_DELIVERY);

    const output = await metricsService.getRegistry().metrics();

    expect(output).toMatch(
      /jobs_completed_total\{type="webhook_delivery"\} 1/,
    );
  });

  it('should clear an alert by setting the gauge back to 0', async () => {
    service.setDlqAlertActive(JobType.WEBHOOK_DELIVERY, 'depth', true);
    service.setDlqAlertActive(JobType.WEBHOOK_DELIVERY, 'depth', false);

    const output = await metricsService.getRegistry().metrics();

    expect(output).toMatch(
      /jobs_dlq_alert_active\{type="webhook_delivery",reason="depth"\} 0/,
    );
  });

  it('should not throw when metrics are used before initialization', () => {
    const uninitialized = new JobQueueMetricsService(new MetricsService());

    expect(() => uninitialized.incrementJobsRetried(JobType.WEBHOOK_DELIVERY)).not.toThrow();
    expect(() => uninitialized.setDlqOldestAgeSeconds(JobType.WEBHOOK_DELIVERY, 10)).not.toThrow();
    expect(() =>
      uninitialized.setDlqAlertActive(JobType.WEBHOOK_DELIVERY, 'depth', true),
    ).not.toThrow();
  });
});
