/**
 * Job Queue System - Job Executor Unit Tests
 * 
 * Tests for the JobExecutor service focusing on:
 * - Cron-based polling for due jobs
 * - Query logic for pending jobs with expired visibility timeout
 * - Processing up to 100 jobs per poll
 * 
 * **Validates: Requirements 4.6, 12.4**
 */

import { Test, TestingModule } from '@nestjs/testing';
import { JobExecutor } from './job-executor.service';
import { JobRepository } from './job.repository';
import { JobRegistry } from './job-registry.service';
import { CancellationStore } from './cancellation-token';
import { JobQueueMetricsService } from './job-queue-metrics.service';
import { Job, JobType, JobStatus } from './types';

describe('JobExecutor', () => {
  let executor: JobExecutor;
  let repository: jest.Mocked<JobRepository>;
  let registry: jest.Mocked<JobRegistry>;
  let cancellationStore: jest.Mocked<CancellationStore>;
  let metrics: jest.Mocked<JobQueueMetricsService>;

  beforeEach(async () => {
    // Create mock implementations
    const mockRepository = {
      findDueJobs: jest.fn(),
      updateJobStatus: jest.fn(),
      resetStaleJobs: jest.fn(),
    };

    const mockRegistry = {
      getHandler: jest.fn(),
      getPolicy: jest.fn(),
      isRegistered: jest.fn(),
    };

    const mockCancellationStore = {
      createToken: jest.fn(),
      requestCancellation: jest.fn(),
      clearCancellation: jest.fn(),
    };

    const mockMetrics = {
      incrementJobsEnqueued: jest.fn(),
      incrementJobsCompleted: jest.fn(),
      incrementJobsFailed: jest.fn(),
      incrementJobsCancelled: jest.fn(),
      updateJobsPendingCount: jest.fn(),
      updateJobsRunningCount: jest.fn(),
      updateJobsDlqCount: jest.fn(),
      recordJobExecutionDuration: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        JobExecutor,
        { provide: JobRepository, useValue: mockRepository },
        { provide: JobRegistry, useValue: mockRegistry },
        { provide: CancellationStore, useValue: mockCancellationStore },
        { provide: JobQueueMetricsService, useValue: mockMetrics },
      ],
    }).compile();

    executor = module.get<JobExecutor>(JobExecutor);
    repository = module.get(JobRepository) as jest.Mocked<JobRepository>;
    registry = module.get(JobRegistry) as jest.Mocked<JobRegistry>;
    cancellationStore = module.get(CancellationStore) as jest.Mocked<CancellationStore>;
    metrics = module.get(JobQueueMetricsService) as jest.Mocked<JobQueueMetricsService>;
  });

  describe('processDueJobs', () => {
    it('should query for due jobs with limit of 100', async () => {
      // Arrange
      repository.findDueJobs.mockResolvedValue([]);

      // Act
      await executor.processDueJobs();

      // Assert
      expect(repository.findDueJobs).toHaveBeenCalledWith(100);
    });

    it('should log when no due jobs are found', async () => {
      // Arrange
      repository.findDueJobs.mockResolvedValue([]);
      const logSpy = jest.spyOn(executor['logger'], 'debug');

      // Act
      await executor.processDueJobs();

      // Assert
      expect(logSpy).toHaveBeenCalledWith('No due jobs found');
    });

    it('should log the number of due jobs found', async () => {
      // Arrange
      const mockJobs: Job[] = [
        createMockJob('job-1', JobType.WEBHOOK_DELIVERY),
        createMockJob('job-2', JobType.RECURRING_PAYMENT),
        createMockJob('job-3', JobType.EXPORT_GENERATION),
      ];
      repository.findDueJobs.mockResolvedValue(mockJobs);
      const logSpy = jest.spyOn(executor['logger'], 'log');

      // Act
      await executor.processDueJobs();

      // Assert
      expect(logSpy).toHaveBeenCalledWith('Found 3 due jobs to process');
    });

    it('should process each due job by locking and executing them', async () => {
      // Arrange
      const mockJobs: Job[] = [
        createMockJob('job-1', JobType.WEBHOOK_DELIVERY),
        createMockJob('job-2', JobType.RECURRING_PAYMENT),
      ];
      repository.findDueJobs.mockResolvedValue(mockJobs);
      
      const mockHandler = {
        execute: jest.fn().mockResolvedValue(undefined),
        validate: jest.fn().mockResolvedValue(undefined),
        onFailure: jest.fn().mockResolvedValue(undefined),
      };
      
      const mockToken = {
        isCancelled: jest.fn().mockReturnValue(false),
        throwIfCancelled: jest.fn(),
      };
      
      registry.getPolicy.mockReturnValue({
        maxAttempts: 3,
        backoffStrategy: 'exponential',
        initialDelayMs: 1000,
        maxDelayMs: 60000,
        visibilityTimeoutMs: 300000, // 5 minutes
      });
      registry.getHandler.mockReturnValue(mockHandler);
      cancellationStore.createToken.mockReturnValue(mockToken);
      repository.updateJobStatus.mockResolvedValue();

      // Act
      await executor.processDueJobs();

      // Assert
      // Verify that each job was locked with visibility timeout
      expect(registry.getPolicy).toHaveBeenCalledWith(JobType.WEBHOOK_DELIVERY);
      expect(registry.getPolicy).toHaveBeenCalledWith(JobType.RECURRING_PAYMENT);
      
      // Each job should be locked (RUNNING) and then completed (COMPLETED)
      expect(repository.updateJobStatus).toHaveBeenCalledTimes(4); // 2 locks + 2 completions
      
      // Verify first job was locked
      expect(repository.updateJobStatus).toHaveBeenCalledWith(
        'job-1',
        JobStatus.RUNNING,
        expect.objectContaining({
          startedAt: expect.any(Date),
          visibilityTimeout: expect.any(Date),
        }),
      );
      
      // Verify first job was completed
      expect(repository.updateJobStatus).toHaveBeenCalledWith(
        'job-1',
        JobStatus.COMPLETED,
        expect.objectContaining({
          completedAt: expect.any(Date),
        }),
      );
      
      // Verify handlers were invoked
      expect(mockHandler.execute).toHaveBeenCalledTimes(2);
      expect(mockHandler.execute).toHaveBeenCalledWith(mockJobs[0], mockToken);
      expect(mockHandler.execute).toHaveBeenCalledWith(mockJobs[1], mockToken);
    });

    it('should handle errors gracefully', async () => {
      // Arrange
      const error = new Error('Database connection failed');
      repository.findDueJobs.mockRejectedValue(error);
      const errorSpy = jest.spyOn(executor['logger'], 'error');

      // Act
      await executor.processDueJobs();

      // Assert
      expect(errorSpy).toHaveBeenCalledWith(
        'Error processing due jobs: Database connection failed',
        expect.any(String),
      );
    });

    it('should prevent concurrent execution', async () => {
      // Arrange
      repository.findDueJobs.mockImplementation(
        () => new Promise((resolve) => setTimeout(() => resolve([]), 100)),
      );
      const debugSpy = jest.spyOn(executor['logger'], 'debug');

      // Act - Start two concurrent polls
      const promise1 = executor.processDueJobs();
      const promise2 = executor.processDueJobs();

      await Promise.all([promise1, promise2]);

      // Assert - Second call should be skipped
      expect(debugSpy).toHaveBeenCalledWith(
        'Skipping poll - previous execution still in progress',
      );
    });

    it('should process up to 100 jobs per poll', async () => {
      // Arrange
      const mockJobs: Job[] = Array.from({ length: 100 }, (_, i) =>
        createMockJob(`job-${i}`, JobType.WEBHOOK_DELIVERY),
      );
      repository.findDueJobs.mockResolvedValue(mockJobs);
      
      const mockHandler = {
        execute: jest.fn().mockResolvedValue(undefined),
        validate: jest.fn().mockResolvedValue(undefined),
        onFailure: jest.fn().mockResolvedValue(undefined),
      };
      
      const mockToken = {
        isCancelled: jest.fn().mockReturnValue(false),
        throwIfCancelled: jest.fn(),
      };
      
      registry.getPolicy.mockReturnValue({
        maxAttempts: 3,
        backoffStrategy: 'exponential',
        initialDelayMs: 1000,
        maxDelayMs: 60000,
        visibilityTimeoutMs: 300000,
      });
      registry.getHandler.mockReturnValue(mockHandler);
      cancellationStore.createToken.mockReturnValue(mockToken);
      repository.updateJobStatus.mockResolvedValue();

      // Act
      await executor.processDueJobs();

      // Assert
      expect(repository.findDueJobs).toHaveBeenCalledWith(100);
      expect(repository.updateJobStatus).toHaveBeenCalledTimes(200); // 100 locks + 100 completions
      expect(mockHandler.execute).toHaveBeenCalledTimes(100);
    });

    it('should handle job locking errors gracefully', async () => {
      // Arrange
      const mockJobs: Job[] = [
        createMockJob('job-1', JobType.WEBHOOK_DELIVERY),
        createMockJob('job-2', JobType.RECURRING_PAYMENT),
      ];
      repository.findDueJobs.mockResolvedValue(mockJobs);
      registry.getPolicy.mockReturnValue({
        maxAttempts: 3,
        backoffStrategy: 'exponential',
        initialDelayMs: 1000,
        maxDelayMs: 60000,
        visibilityTimeoutMs: 300000,
      });
      
      // First job fails to lock, second succeeds
      repository.updateJobStatus
        .mockRejectedValueOnce(new Error('Database lock failed'))
        .mockResolvedValueOnce() // job-2 lock succeeds
        .mockResolvedValueOnce(); // job-2 completion succeeds
      
      const mockHandler = {
        execute: jest.fn().mockResolvedValue(undefined),
        validate: jest.fn().mockResolvedValue(undefined),
        onFailure: jest.fn().mockResolvedValue(undefined),
      };
      
      const mockToken = {
        isCancelled: jest.fn().mockReturnValue(false),
        throwIfCancelled: jest.fn(),
      };
      
      registry.getHandler.mockReturnValue(mockHandler);
      cancellationStore.createToken.mockReturnValue(mockToken);
      
      const errorSpy = jest.spyOn(executor['logger'], 'error');

      // Act
      await executor.processDueJobs();

      // Assert
      // First job should fail with lock error
      expect(errorSpy).toHaveBeenCalledWith(
        expect.stringContaining('Job job-1 failed'),
        expect.any(String),
      );
      expect(errorSpy).toHaveBeenCalledWith(
        expect.stringContaining('Database lock failed'),
        expect.any(String),
      );
      
      // Second job should still be processed successfully
      expect(mockHandler.execute).toHaveBeenCalledWith(mockJobs[1], mockToken);
      expect(repository.updateJobStatus).toHaveBeenCalledWith(
        'job-2',
        JobStatus.COMPLETED,
        expect.any(Object),
      );
    });

    it('should set visibility timeout based on retry policy', async () => {
      // Arrange
      const mockJob = createMockJob('job-1', JobType.WEBHOOK_DELIVERY);
      repository.findDueJobs.mockResolvedValue([mockJob]);
      registry.getPolicy.mockReturnValue({
        maxAttempts: 5,
        backoffStrategy: 'exponential',
        initialDelayMs: 60000,
        maxDelayMs: 7200000,
        visibilityTimeoutMs: 300000, // 5 minutes
      });
      repository.updateJobStatus.mockResolvedValue();

      const beforeExecution = Date.now();

      // Act
      await executor.processDueJobs();

      // Assert
      expect(repository.updateJobStatus).toHaveBeenCalledWith(
        'job-1',
        JobStatus.RUNNING,
        expect.objectContaining({
          startedAt: expect.any(Date),
          visibilityTimeout: expect.any(Date),
        }),
      );

      // Verify visibility timeout is approximately 5 minutes in the future
      const call = repository.updateJobStatus.mock.calls[0];
      const updates = call[2] as { visibilityTimeout: Date };
      const visibilityTimeoutMs = updates.visibilityTimeout.getTime() - beforeExecution;
      
      // Allow 1 second tolerance for test execution time
      expect(visibilityTimeoutMs).toBeGreaterThanOrEqual(299000);
      expect(visibilityTimeoutMs).toBeLessThanOrEqual(301000);
    });

    it('should record startedAt timestamp when locking job', async () => {
      // Arrange
      const mockJob = createMockJob('job-1', JobType.WEBHOOK_DELIVERY);
      repository.findDueJobs.mockResolvedValue([mockJob]);
      registry.getPolicy.mockReturnValue({
        maxAttempts: 3,
        backoffStrategy: 'exponential',
        initialDelayMs: 1000,
        maxDelayMs: 60000,
        visibilityTimeoutMs: 300000,
      });
      repository.updateJobStatus.mockResolvedValue();

      const beforeExecution = Date.now();

      // Act
      await executor.processDueJobs();

      // Assert
      const call = repository.updateJobStatus.mock.calls[0];
      const updates = call[2] as { startedAt: Date };
      const startedAtMs = updates.startedAt.getTime();
      
      // Verify startedAt is close to current time (within 1 second)
      expect(startedAtMs).toBeGreaterThanOrEqual(beforeExecution);
      expect(startedAtMs).toBeLessThanOrEqual(Date.now());
    });

    it('should log job locking with attempt information', async () => {
      // Arrange
      const mockJob = createMockJob('job-1', JobType.WEBHOOK_DELIVERY);
      mockJob.attempts = 2; // This is the 3rd attempt
      repository.findDueJobs.mockResolvedValue([mockJob]);
      
      const mockHandler = {
        execute: jest.fn().mockResolvedValue(undefined),
        validate: jest.fn().mockResolvedValue(undefined),
        onFailure: jest.fn().mockResolvedValue(undefined),
      };
      
      const mockToken = {
        isCancelled: jest.fn().mockReturnValue(false),
        throwIfCancelled: jest.fn(),
      };
      
      registry.getPolicy.mockReturnValue({
        maxAttempts: 5,
        backoffStrategy: 'exponential',
        initialDelayMs: 1000,
        maxDelayMs: 60000,
        visibilityTimeoutMs: 300000,
      });
      registry.getHandler.mockReturnValue(mockHandler);
      cancellationStore.createToken.mockReturnValue(mockToken);
      repository.updateJobStatus.mockResolvedValue();
      const logSpy = jest.spyOn(executor['logger'], 'log');

      // Act
      await executor.processDueJobs();

      // Assert
      expect(logSpy).toHaveBeenCalledWith(
        expect.stringContaining('Job job-1 locked for execution'),
      );
      expect(logSpy).toHaveBeenCalledWith(
        expect.stringContaining('attempt: 3/5'),
      );
    });
  });

  describe('executeJob - success flow', () => {
    it('should mark job as completed when handler succeeds', async () => {
      // Arrange
      const mockJob = createMockJob('job-1', JobType.WEBHOOK_DELIVERY);
      repository.findDueJobs.mockResolvedValue([mockJob]);
      
      const mockHandler = {
        execute: jest.fn().mockResolvedValue(undefined),
        validate: jest.fn().mockResolvedValue(undefined),
        onFailure: jest.fn().mockResolvedValue(undefined),
      };
      
      const mockToken = {
        isCancelled: jest.fn().mockReturnValue(false),
        throwIfCancelled: jest.fn(),
      };
      
      registry.getPolicy.mockReturnValue({
        maxAttempts: 3,
        backoffStrategy: 'exponential',
        initialDelayMs: 1000,
        maxDelayMs: 60000,
        visibilityTimeoutMs: 300000,
      });
      registry.getHandler.mockReturnValue(mockHandler);
      cancellationStore.createToken.mockReturnValue(mockToken);
      repository.updateJobStatus.mockResolvedValue();

      // Act
      await executor.processDueJobs();

      // Assert
      expect(mockHandler.execute).toHaveBeenCalledWith(mockJob, mockToken);
      expect(repository.updateJobStatus).toHaveBeenCalledWith(
        'job-1',
        JobStatus.COMPLETED,
        expect.objectContaining({
          completedAt: expect.any(Date),
        }),
      );
      expect(cancellationStore.clearCancellation).toHaveBeenCalledWith('job-1');
    });

    it('should log successful job completion with duration', async () => {
      // Arrange
      const mockJob = createMockJob('job-1', JobType.WEBHOOK_DELIVERY);
      repository.findDueJobs.mockResolvedValue([mockJob]);
      
      const mockHandler = {
        execute: jest.fn().mockResolvedValue(undefined),
        validate: jest.fn().mockResolvedValue(undefined),
        onFailure: jest.fn().mockResolvedValue(undefined),
      };
      
      const mockToken = {
        isCancelled: jest.fn().mockReturnValue(false),
        throwIfCancelled: jest.fn(),
      };
      
      registry.getPolicy.mockReturnValue({
        maxAttempts: 3,
        backoffStrategy: 'exponential',
        initialDelayMs: 1000,
        maxDelayMs: 60000,
        visibilityTimeoutMs: 300000,
      });
      registry.getHandler.mockReturnValue(mockHandler);
      cancellationStore.createToken.mockReturnValue(mockToken);
      repository.updateJobStatus.mockResolvedValue();
      const logSpy = jest.spyOn(executor['logger'], 'log');

      // Act
      await executor.processDueJobs();

      // Assert
      expect(logSpy).toHaveBeenCalledWith(
        expect.stringContaining('Job job-1 completed successfully'),
      );
      expect(logSpy).toHaveBeenCalledWith(
        expect.stringContaining('duration:'),
      );
    });
  });

  describe('executeJob - failure flow', () => {
    it('should schedule retry when handler fails and attempts < maxAttempts', async () => {
      // Arrange
      const mockJob = createMockJob('job-1', JobType.WEBHOOK_DELIVERY);
      mockJob.attempts = 0; // First attempt
      repository.findDueJobs.mockResolvedValue([mockJob]);
      
      const mockHandler = {
        execute: jest.fn().mockRejectedValue(new Error('Network timeout')),
        validate: jest.fn().mockResolvedValue(undefined),
        onFailure: jest.fn().mockResolvedValue(undefined),
      };
      
      const mockToken = {
        isCancelled: jest.fn().mockReturnValue(false),
        throwIfCancelled: jest.fn(),
      };
      
      registry.getPolicy.mockReturnValue({
        maxAttempts: 3,
        backoffStrategy: 'exponential',
        initialDelayMs: 1000,
        maxDelayMs: 60000,
        visibilityTimeoutMs: 300000,
      });
      registry.getHandler.mockReturnValue(mockHandler);
      cancellationStore.createToken.mockReturnValue(mockToken);
      repository.updateJobStatus.mockResolvedValue();

      const beforeExecution = Date.now();

      // Act
      await executor.processDueJobs();

      // Assert
      expect(mockHandler.execute).toHaveBeenCalledWith(mockJob, mockToken);
      
      // Should update to PENDING with incremented attempts and new scheduledAt
      expect(repository.updateJobStatus).toHaveBeenCalledWith(
        'job-1',
        JobStatus.PENDING,
        expect.objectContaining({
          attempts: 1,
          failureReason: 'Network timeout',
          scheduledAt: expect.any(Date),
          visibilityTimeout: null,
        }),
      );

      // Verify retry delay (exponential: 1000ms for first retry)
      const call = repository.updateJobStatus.mock.calls.find(
        c => c[1] === JobStatus.PENDING,
      );
      const updates = call[2] as { scheduledAt: Date };
      const retryDelayMs = updates.scheduledAt.getTime() - beforeExecution;
      
      // Allow 100ms tolerance for test execution time
      expect(retryDelayMs).toBeGreaterThanOrEqual(900);
      expect(retryDelayMs).toBeLessThanOrEqual(1100);
      
      expect(cancellationStore.clearCancellation).toHaveBeenCalledWith('job-1');
    });

    it('should move job to DLQ when attempts >= maxAttempts', async () => {
      // Arrange
      const mockJob = createMockJob('job-1', JobType.WEBHOOK_DELIVERY);
      mockJob.attempts = 2; // Third attempt will exceed maxAttempts=3
      repository.findDueJobs.mockResolvedValue([mockJob]);
      
      const mockHandler = {
        execute: jest.fn().mockRejectedValue(new Error('Permanent failure')),
        validate: jest.fn().mockResolvedValue(undefined),
        onFailure: jest.fn().mockResolvedValue(undefined),
      };
      
      const mockToken = {
        isCancelled: jest.fn().mockReturnValue(false),
        throwIfCancelled: jest.fn(),
      };
      
      registry.getPolicy.mockReturnValue({
        maxAttempts: 3,
        backoffStrategy: 'exponential',
        initialDelayMs: 1000,
        maxDelayMs: 60000,
        visibilityTimeoutMs: 300000,
      });
      registry.getHandler.mockReturnValue(mockHandler);
      cancellationStore.createToken.mockReturnValue(mockToken);
      repository.updateJobStatus.mockResolvedValue();

      // Act
      await executor.processDueJobs();

      // Assert
      expect(mockHandler.execute).toHaveBeenCalledWith(mockJob, mockToken);
      
      // Should update to FAILED with incremented attempts and completedAt
      expect(repository.updateJobStatus).toHaveBeenCalledWith(
        'job-1',
        JobStatus.FAILED,
        expect.objectContaining({
          attempts: 3,
          failureReason: 'Permanent failure',
          completedAt: expect.any(Date),
        }),
      );
      
      // Should call onFailure hook
      expect(mockHandler.onFailure).toHaveBeenCalledWith(
        mockJob,
        expect.objectContaining({ message: 'Permanent failure' }),
      );
      
      expect(cancellationStore.clearCancellation).toHaveBeenCalledWith('job-1');
    });

    it('should log failure with attempt information', async () => {
      // Arrange
      const mockJob = createMockJob('job-1', JobType.WEBHOOK_DELIVERY);
      mockJob.attempts = 1;
      repository.findDueJobs.mockResolvedValue([mockJob]);
      
      const mockHandler = {
        execute: jest.fn().mockRejectedValue(new Error('Service unavailable')),
        validate: jest.fn().mockResolvedValue(undefined),
        onFailure: jest.fn().mockResolvedValue(undefined),
      };
      
      const mockToken = {
        isCancelled: jest.fn().mockReturnValue(false),
        throwIfCancelled: jest.fn(),
      };
      
      registry.getPolicy.mockReturnValue({
        maxAttempts: 5,
        backoffStrategy: 'exponential',
        initialDelayMs: 1000,
        maxDelayMs: 60000,
        visibilityTimeoutMs: 300000,
      });
      registry.getHandler.mockReturnValue(mockHandler);
      cancellationStore.createToken.mockReturnValue(mockToken);
      repository.updateJobStatus.mockResolvedValue();
      const errorSpy = jest.spyOn(executor['logger'], 'error');

      // Act
      await executor.processDueJobs();

      // Assert
      expect(errorSpy).toHaveBeenCalledWith(
        expect.stringContaining('Job job-1 failed'),
        expect.any(String),
      );
      expect(errorSpy).toHaveBeenCalledWith(
        expect.stringContaining('attempt: 2/5'),
        expect.any(String),
      );
      expect(errorSpy).toHaveBeenCalledWith(
        expect.stringContaining('Service unavailable'),
        expect.any(String),
      );
    });

    it('should log warning when job moved to DLQ', async () => {
      // Arrange
      const mockJob = createMockJob('job-1', JobType.WEBHOOK_DELIVERY);
      mockJob.attempts = 2;
      repository.findDueJobs.mockResolvedValue([mockJob]);
      
      const mockHandler = {
        execute: jest.fn().mockRejectedValue(new Error('Final failure')),
        validate: jest.fn().mockResolvedValue(undefined),
        onFailure: jest.fn().mockResolvedValue(undefined),
      };
      
      const mockToken = {
        isCancelled: jest.fn().mockReturnValue(false),
        throwIfCancelled: jest.fn(),
      };
      
      registry.getPolicy.mockReturnValue({
        maxAttempts: 3,
        backoffStrategy: 'exponential',
        initialDelayMs: 1000,
        maxDelayMs: 60000,
        visibilityTimeoutMs: 300000,
      });
      registry.getHandler.mockReturnValue(mockHandler);
      cancellationStore.createToken.mockReturnValue(mockToken);
      repository.updateJobStatus.mockResolvedValue();
      const warnSpy = jest.spyOn(executor['logger'], 'warn');

      // Act
      await executor.processDueJobs();

      // Assert
      expect(warnSpy).toHaveBeenCalledWith(
        expect.stringContaining('Job job-1 moved to DLQ after 3 attempts'),
      );
    });

    it('should handle onFailure hook errors gracefully', async () => {
      // Arrange
      const mockJob = createMockJob('job-1', JobType.WEBHOOK_DELIVERY);
      mockJob.attempts = 2;
      repository.findDueJobs.mockResolvedValue([mockJob]);
      
      const mockHandler = {
        execute: jest.fn().mockRejectedValue(new Error('Job failed')),
        validate: jest.fn().mockResolvedValue(undefined),
        onFailure: jest.fn().mockRejectedValue(new Error('Hook failed')),
      };
      
      const mockToken = {
        isCancelled: jest.fn().mockReturnValue(false),
        throwIfCancelled: jest.fn(),
      };
      
      registry.getPolicy.mockReturnValue({
        maxAttempts: 3,
        backoffStrategy: 'exponential',
        initialDelayMs: 1000,
        maxDelayMs: 60000,
        visibilityTimeoutMs: 300000,
      });
      registry.getHandler.mockReturnValue(mockHandler);
      cancellationStore.createToken.mockReturnValue(mockToken);
      repository.updateJobStatus.mockResolvedValue();
      const errorSpy = jest.spyOn(executor['logger'], 'error');

      // Act
      await executor.processDueJobs();

      // Assert
      expect(mockHandler.onFailure).toHaveBeenCalled();
      expect(errorSpy).toHaveBeenCalledWith(
        expect.stringContaining('Failed to execute onFailure hook for job job-1'),
        expect.any(String),
      );
      // Job should still be marked as FAILED
      expect(repository.updateJobStatus).toHaveBeenCalledWith(
        'job-1',
        JobStatus.FAILED,
        expect.any(Object),
      );
    });

    it('should calculate exponential backoff correctly for retries', async () => {
      // Arrange
      const mockJob = createMockJob('job-1', JobType.WEBHOOK_DELIVERY);
      mockJob.attempts = 2; // Third attempt
      repository.findDueJobs.mockResolvedValue([mockJob]);
      
      const mockHandler = {
        execute: jest.fn().mockRejectedValue(new Error('Retry me')),
        validate: jest.fn().mockResolvedValue(undefined),
        onFailure: jest.fn().mockResolvedValue(undefined),
      };
      
      const mockToken = {
        isCancelled: jest.fn().mockReturnValue(false),
        throwIfCancelled: jest.fn(),
      };
      
      registry.getPolicy.mockReturnValue({
        maxAttempts: 5,
        backoffStrategy: 'exponential',
        initialDelayMs: 1000,
        maxDelayMs: 60000,
        visibilityTimeoutMs: 300000,
      });
      registry.getHandler.mockReturnValue(mockHandler);
      cancellationStore.createToken.mockReturnValue(mockToken);
      repository.updateJobStatus.mockResolvedValue();

      const beforeExecution = Date.now();

      // Act
      await executor.processDueJobs();

      // Assert
      const call = repository.updateJobStatus.mock.calls.find(
        c => c[1] === JobStatus.PENDING,
      );
      const updates = call[2] as { scheduledAt: Date };
      const retryDelayMs = updates.scheduledAt.getTime() - beforeExecution;
      
      // Exponential backoff for attempt 3: 1000 * 2^(3-1) = 4000ms
      expect(retryDelayMs).toBeGreaterThanOrEqual(3900);
      expect(retryDelayMs).toBeLessThanOrEqual(4100);
    });

    it('should not retry when maxAttempts is 0 (unlimited)', async () => {
      // Arrange
      const mockJob = createMockJob('job-1', JobType.STELLAR_RECONNECT);
      mockJob.attempts = 100; // Many attempts
      repository.findDueJobs.mockResolvedValue([mockJob]);
      
      const mockHandler = {
        execute: jest.fn().mockRejectedValue(new Error('Keep retrying')),
        validate: jest.fn().mockResolvedValue(undefined),
        onFailure: jest.fn().mockResolvedValue(undefined),
      };
      
      const mockToken = {
        isCancelled: jest.fn().mockReturnValue(false),
        throwIfCancelled: jest.fn(),
      };
      
      registry.getPolicy.mockReturnValue({
        maxAttempts: 0, // Unlimited retries
        backoffStrategy: 'exponential',
        initialDelayMs: 1000,
        maxDelayMs: 60000,
        visibilityTimeoutMs: 120000,
      });
      registry.getHandler.mockReturnValue(mockHandler);
      cancellationStore.createToken.mockReturnValue(mockToken);
      repository.updateJobStatus.mockResolvedValue();

      // Act
      await executor.processDueJobs();

      // Assert
      // Should schedule retry, not move to DLQ
      expect(repository.updateJobStatus).toHaveBeenCalledWith(
        'job-1',
        JobStatus.PENDING,
        expect.objectContaining({
          attempts: 101,
          failureReason: 'Keep retrying',
        }),
      );
      expect(mockHandler.onFailure).not.toHaveBeenCalled();
    });

    it('should treat expired visibility timeout as job failure', async () => {
      // Arrange
      const mockJob = createMockJob('job-1', JobType.WEBHOOK_DELIVERY);
      mockJob.attempts = 1;
      mockJob.visibilityTimeout = new Date(Date.now() - 60000); // Expired 1 minute ago
      repository.findDueJobs.mockResolvedValue([mockJob]);
      
      const mockHandler = {
        execute: jest.fn().mockResolvedValue(undefined),
        validate: jest.fn().mockResolvedValue(undefined),
        onFailure: jest.fn().mockResolvedValue(undefined),
      };
      
      const mockToken = {
        isCancelled: jest.fn().mockReturnValue(false),
        throwIfCancelled: jest.fn(),
      };
      
      registry.getPolicy.mockReturnValue({
        maxAttempts: 3,
        backoffStrategy: 'exponential',
        initialDelayMs: 1000,
        maxDelayMs: 60000,
        visibilityTimeoutMs: 300000,
      });
      registry.getHandler.mockReturnValue(mockHandler);
      cancellationStore.createToken.mockReturnValue(mockToken);
      repository.updateJobStatus.mockResolvedValue();
      const warnSpy = jest.spyOn(executor['logger'], 'warn');

      const beforeExecution = Date.now();

      // Act
      await executor.processDueJobs();

      // Assert
      // Should log warning about expired visibility timeout
      expect(warnSpy).toHaveBeenCalledWith(
        expect.stringContaining('Job job-1 has expired visibility timeout'),
      );
      
      // Should NOT execute the handler (timeout already occurred)
      expect(mockHandler.execute).not.toHaveBeenCalled();
      
      // Should schedule retry with incremented attempts
      expect(repository.updateJobStatus).toHaveBeenCalledWith(
        'job-1',
        JobStatus.PENDING,
        expect.objectContaining({
          attempts: 2,
          failureReason: expect.stringContaining('Visibility timeout expired'),
          scheduledAt: expect.any(Date),
          visibilityTimeout: null,
        }),
      );

      // Verify retry delay (exponential: 1000 * 2^(2-1) = 2000ms for second retry)
      const call = repository.updateJobStatus.mock.calls.find(
        c => c[1] === JobStatus.PENDING,
      );
      const updates = call[2] as { scheduledAt: Date };
      const retryDelayMs = updates.scheduledAt.getTime() - beforeExecution;
      
      expect(retryDelayMs).toBeGreaterThanOrEqual(1900);
      expect(retryDelayMs).toBeLessThanOrEqual(2100);
    });

    it('should move job to DLQ when visibility timeout expires and maxAttempts exceeded', async () => {
      // Arrange
      const mockJob = createMockJob('job-1', JobType.WEBHOOK_DELIVERY);
      mockJob.attempts = 2; // Third attempt will exceed maxAttempts=3
      mockJob.visibilityTimeout = new Date(Date.now() - 120000); // Expired 2 minutes ago
      repository.findDueJobs.mockResolvedValue([mockJob]);
      
      const mockHandler = {
        execute: jest.fn().mockResolvedValue(undefined),
        validate: jest.fn().mockResolvedValue(undefined),
        onFailure: jest.fn().mockResolvedValue(undefined),
      };
      
      const mockToken = {
        isCancelled: jest.fn().mockReturnValue(false),
        throwIfCancelled: jest.fn(),
      };
      
      registry.getPolicy.mockReturnValue({
        maxAttempts: 3,
        backoffStrategy: 'exponential',
        initialDelayMs: 1000,
        maxDelayMs: 60000,
        visibilityTimeoutMs: 300000,
      });
      registry.getHandler.mockReturnValue(mockHandler);
      cancellationStore.createToken.mockReturnValue(mockToken);
      repository.updateJobStatus.mockResolvedValue();
      const warnSpy = jest.spyOn(executor['logger'], 'warn');

      // Act
      await executor.processDueJobs();

      // Assert
      // Should log warning about expired visibility timeout
      expect(warnSpy).toHaveBeenCalledWith(
        expect.stringContaining('Job job-1 has expired visibility timeout'),
      );
      
      // Should NOT execute the handler
      expect(mockHandler.execute).not.toHaveBeenCalled();
      
      // Should move to DLQ (FAILED status)
      expect(repository.updateJobStatus).toHaveBeenCalledWith(
        'job-1',
        JobStatus.FAILED,
        expect.objectContaining({
          attempts: 3,
          failureReason: expect.stringContaining('Visibility timeout expired'),
          completedAt: expect.any(Date),
        }),
      );
      
      // Should call onFailure hook
      expect(mockHandler.onFailure).toHaveBeenCalledWith(
        mockJob,
        expect.objectContaining({ 
          message: expect.stringContaining('Visibility timeout expired'),
        }),
      );
      
      // Should log DLQ warning
      expect(warnSpy).toHaveBeenCalledWith(
        expect.stringContaining('Job job-1 moved to DLQ after 3 attempts'),
      );
    });
  });

  describe('onModuleInit', () => {
    it('should log initialization message', async () => {
      // Arrange
      const logSpy = jest.spyOn(executor['logger'], 'log');
      repository.resetStaleJobs.mockResolvedValue(0);

      // Act
      await executor.onModuleInit();

      // Assert
      expect(logSpy).toHaveBeenCalledWith('JobExecutor initialized');
    });

    it('should call resetStaleJobs on startup', async () => {
      // Arrange
      repository.resetStaleJobs.mockResolvedValue(0);

      // Act
      await executor.onModuleInit();

      // Assert
      expect(repository.resetStaleJobs).toHaveBeenCalled();
    });

    it('should log when no stale jobs are found', async () => {
      // Arrange
      repository.resetStaleJobs.mockResolvedValue(0);
      const logSpy = jest.spyOn(executor['logger'], 'log');

      // Act
      await executor.onModuleInit();

      // Assert
      expect(logSpy).toHaveBeenCalledWith('No stale jobs found on startup');
    });

    it('should log warning when stale jobs are reset', async () => {
      // Arrange
      repository.resetStaleJobs.mockResolvedValue(5);
      const warnSpy = jest.spyOn(executor['logger'], 'warn');

      // Act
      await executor.onModuleInit();

      // Assert
      expect(warnSpy).toHaveBeenCalledWith('Reset 5 stale jobs on startup');
    });

    it('should handle resetStaleJobs errors gracefully', async () => {
      // Arrange
      const error = new Error('Database connection failed');
      repository.resetStaleJobs.mockRejectedValue(error);
      const errorSpy = jest.spyOn(executor['logger'], 'error');

      // Act
      await executor.onModuleInit();

      // Assert
      expect(errorSpy).toHaveBeenCalledWith(
        'Failed to reset stale jobs on startup: Database connection failed',
        expect.any(String),
      );
    });

    it('should not throw when resetStaleJobs fails', async () => {
      // Arrange
      const error = new Error('Database connection failed');
      repository.resetStaleJobs.mockRejectedValue(error);

      // Act & Assert
      await expect(executor.onModuleInit()).resolves.not.toThrow();
    });
  });
});

/**
 * Helper function to create a mock job for testing
 */
function createMockJob(id: string, type: JobType): Job {
  return {
    id,
    type,
    payload: {},
    status: JobStatus.PENDING,
    attempts: 0,
    maxAttempts: 3,
    createdAt: new Date(),
    scheduledAt: new Date(),
    startedAt: null,
    completedAt: null,
    failureReason: null,
    visibilityTimeout: null,
  };
}
