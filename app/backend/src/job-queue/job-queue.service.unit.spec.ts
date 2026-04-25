/**
 * Job Queue Service - Unit Tests
 * 
 * Tests for the JobQueueService that provides the main public API for job queue operations.
 * 
 * **Validates: Requirements 2.1, 2.3, 2.4, 6.1, 6.2, 15.2**
 */

import { Test, TestingModule } from '@nestjs/testing';
import { JobQueueService, UnregisteredJobTypeError, PayloadValidationError } from './job-queue.service';
import { JobRepository } from './job.repository';
import { JobRegistry } from './job-registry.service';
import { CancellationStore } from './cancellation-token';
import { JobQueueMetricsService } from './job-queue-metrics.service';
import { JobType, JobStatus, Job, JobHandler, RetryPolicy } from './types';

describe('JobQueueService', () => {
  let service: JobQueueService;
  let repository: jest.Mocked<JobRepository>;
  let registry: jest.Mocked<JobRegistry>;
  let cancellationStore: jest.Mocked<CancellationStore>;
  let metrics: jest.Mocked<JobQueueMetricsService>;

  // Mock handler
  const mockHandler: JobHandler = {
    execute: jest.fn(),
    validate: jest.fn().mockResolvedValue(undefined),
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
    // Create mock implementations
    const mockRepository = {
      createJob: jest.fn(),
      updateJobStatus: jest.fn(),
      findById: jest.fn(),
      listJobs: jest.fn(),
      findDueJobs: jest.fn(),
      resetStaleJobs: jest.fn(),
    };

    const mockRegistry = {
      registerHandler: jest.fn(),
      getHandler: jest.fn(),
      getPolicy: jest.fn(),
      isRegistered: jest.fn(),
      getRegisteredTypes: jest.fn(),
      clear: jest.fn(),
    };

    const mockCancellationStore = {
      requestCancellation: jest.fn(),
      isCancelled: jest.fn(),
      clearCancellation: jest.fn(),
      createToken: jest.fn(),
      getActiveCount: jest.fn(),
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
        JobQueueService,
        { provide: JobRepository, useValue: mockRepository },
        { provide: JobRegistry, useValue: mockRegistry },
        { provide: CancellationStore, useValue: mockCancellationStore },
        { provide: JobQueueMetricsService, useValue: mockMetrics },
      ],
    }).compile();

    service = module.get<JobQueueService>(JobQueueService);
    repository = module.get(JobRepository) as jest.Mocked<JobRepository>;
    registry = module.get(JobRegistry) as jest.Mocked<JobRegistry>;
    cancellationStore = module.get(CancellationStore) as jest.Mocked<CancellationStore>;
    metrics = module.get(JobQueueMetricsService) as jest.Mocked<JobQueueMetricsService>;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('enqueue', () => {
    it('should create job with correct status and scheduled_at (immediate execution)', async () => {
      // Arrange
      const payload = { webhookUrl: 'https://example.com', eventType: 'payment' };
      const mockJob: Job = {
        id: 'job-123',
        type: JobType.WEBHOOK_DELIVERY,
        payload,
        status: JobStatus.PENDING,
        attempts: 0,
        maxAttempts: 5,
        createdAt: new Date(),
        scheduledAt: new Date(),
        startedAt: null,
        completedAt: null,
        failureReason: null,
        visibilityTimeout: null,
      };

      registry.isRegistered.mockReturnValue(true);
      registry.getHandler.mockReturnValue(mockHandler);
      registry.getPolicy.mockReturnValue(mockPolicy);
      repository.createJob.mockResolvedValue(mockJob);

      // Act
      const jobId = await service.enqueue(JobType.WEBHOOK_DELIVERY, payload);

      // Assert
      expect(jobId).toBe('job-123');
      expect(registry.isRegistered).toHaveBeenCalledWith(JobType.WEBHOOK_DELIVERY);
      expect(mockHandler.validate).toHaveBeenCalledWith(payload);
      expect(repository.createJob).toHaveBeenCalledWith(
        JobType.WEBHOOK_DELIVERY,
        payload,
        5, // maxAttempts from policy
        expect.any(Date), // scheduledAt should be approximately now
      );
    });

    it('should validate payload before creating job', async () => {
      // Arrange
      const payload = { webhookUrl: 'https://example.com', eventType: 'payment' };
      const mockJob: Job = {
        id: 'job-123',
        type: JobType.WEBHOOK_DELIVERY,
        payload,
        status: JobStatus.PENDING,
        attempts: 0,
        maxAttempts: 5,
        createdAt: new Date(),
        scheduledAt: new Date(),
        startedAt: null,
        completedAt: null,
        failureReason: null,
        visibilityTimeout: null,
      };

      registry.isRegistered.mockReturnValue(true);
      registry.getHandler.mockReturnValue(mockHandler);
      registry.getPolicy.mockReturnValue(mockPolicy);
      repository.createJob.mockResolvedValue(mockJob);

      // Act
      await service.enqueue(JobType.WEBHOOK_DELIVERY, payload);

      // Assert
      expect(mockHandler.validate).toHaveBeenCalledWith(payload);
      expect(repository.createJob).toHaveBeenCalled();
    });

    it('should reject invalid payloads with PayloadValidationError', async () => {
      // Arrange
      const payload = { invalid: 'data' };
      const validationError = new Error('Missing required field: webhookUrl');

      registry.isRegistered.mockReturnValue(true);
      registry.getHandler.mockReturnValue({
        ...mockHandler,
        validate: jest.fn().mockRejectedValue(validationError),
      });

      // Act & Assert
      await expect(
        service.enqueue(JobType.WEBHOOK_DELIVERY, payload),
      ).rejects.toThrow(PayloadValidationError);
      await expect(
        service.enqueue(JobType.WEBHOOK_DELIVERY, payload),
      ).rejects.toThrow('Payload validation failed: Missing required field: webhookUrl');

      expect(repository.createJob).not.toHaveBeenCalled();
    });

    it('should reject unregistered job types with UnregisteredJobTypeError', async () => {
      // Arrange
      const payload = { data: 'test' };
      registry.isRegistered.mockReturnValue(false);

      // Act & Assert
      await expect(
        service.enqueue(JobType.WEBHOOK_DELIVERY, payload),
      ).rejects.toThrow(UnregisteredJobTypeError);
      await expect(
        service.enqueue(JobType.WEBHOOK_DELIVERY, payload),
      ).rejects.toThrow("Job type 'webhook_delivery' is not registered");

      expect(mockHandler.validate).not.toHaveBeenCalled();
      expect(repository.createJob).not.toHaveBeenCalled();
    });
  });

  describe('enqueueDelayed', () => {
    it('should create job with specified scheduled_at timestamp', async () => {
      // Arrange
      const payload = { webhookUrl: 'https://example.com', eventType: 'payment' };
      const scheduledAt = new Date('2026-12-31T23:59:59Z');
      const mockJob: Job = {
        id: 'job-456',
        type: JobType.WEBHOOK_DELIVERY,
        payload,
        status: JobStatus.PENDING,
        attempts: 0,
        maxAttempts: 5,
        createdAt: new Date(),
        scheduledAt,
        startedAt: null,
        completedAt: null,
        failureReason: null,
        visibilityTimeout: null,
      };

      registry.isRegistered.mockReturnValue(true);
      registry.getHandler.mockReturnValue(mockHandler);
      registry.getPolicy.mockReturnValue(mockPolicy);
      repository.createJob.mockResolvedValue(mockJob);

      // Act
      const jobId = await service.enqueueDelayed(
        JobType.WEBHOOK_DELIVERY,
        payload,
        scheduledAt,
      );

      // Assert
      expect(jobId).toBe('job-456');
      expect(repository.createJob).toHaveBeenCalledWith(
        JobType.WEBHOOK_DELIVERY,
        payload,
        5,
        scheduledAt,
      );
    });

    it('should validate payload for delayed jobs', async () => {
      // Arrange
      const payload = { invalid: 'data' };
      const scheduledAt = new Date('2026-12-31T23:59:59Z');
      const validationError = new Error('Invalid payload');

      registry.isRegistered.mockReturnValue(true);
      registry.getHandler.mockReturnValue({
        ...mockHandler,
        validate: jest.fn().mockRejectedValue(validationError),
      });

      // Act & Assert
      await expect(
        service.enqueueDelayed(JobType.WEBHOOK_DELIVERY, payload, scheduledAt),
      ).rejects.toThrow(PayloadValidationError);

      expect(repository.createJob).not.toHaveBeenCalled();
    });
  });

  describe('cancel', () => {
    it('should update pending job to cancelled immediately', async () => {
      // Arrange
      const mockJob: Job = {
        id: 'job-123',
        type: JobType.WEBHOOK_DELIVERY,
        payload: {},
        status: JobStatus.PENDING,
        attempts: 0,
        maxAttempts: 5,
        createdAt: new Date(),
        scheduledAt: new Date(),
        startedAt: null,
        completedAt: null,
        failureReason: null,
        visibilityTimeout: null,
      };

      repository.findById.mockResolvedValue(mockJob);

      // Act
      await service.cancel('job-123');

      // Assert
      expect(repository.findById).toHaveBeenCalledWith('job-123');
      expect(repository.updateJobStatus).toHaveBeenCalledWith(
        'job-123',
        JobStatus.CANCELLED,
        { completedAt: expect.any(Date) },
      );
      expect(cancellationStore.requestCancellation).not.toHaveBeenCalled();
    });

    it('should set cancellation token for running job', async () => {
      // Arrange
      const mockJob: Job = {
        id: 'job-456',
        type: JobType.WEBHOOK_DELIVERY,
        payload: {},
        status: JobStatus.RUNNING,
        attempts: 1,
        maxAttempts: 5,
        createdAt: new Date(),
        scheduledAt: new Date(),
        startedAt: new Date(),
        completedAt: null,
        failureReason: null,
        visibilityTimeout: new Date(Date.now() + 300000),
      };

      repository.findById.mockResolvedValue(mockJob);

      // Act
      await service.cancel('job-456');

      // Assert
      expect(repository.findById).toHaveBeenCalledWith('job-456');
      expect(cancellationStore.requestCancellation).toHaveBeenCalledWith('job-456');
      expect(repository.updateJobStatus).not.toHaveBeenCalled();
    });

    it('should not cancel completed jobs', async () => {
      // Arrange
      const mockJob: Job = {
        id: 'job-789',
        type: JobType.WEBHOOK_DELIVERY,
        payload: {},
        status: JobStatus.COMPLETED,
        attempts: 1,
        maxAttempts: 5,
        createdAt: new Date(),
        scheduledAt: new Date(),
        startedAt: new Date(),
        completedAt: new Date(),
        failureReason: null,
        visibilityTimeout: null,
      };

      repository.findById.mockResolvedValue(mockJob);

      // Act
      await service.cancel('job-789');

      // Assert
      expect(repository.findById).toHaveBeenCalledWith('job-789');
      expect(repository.updateJobStatus).not.toHaveBeenCalled();
      expect(cancellationStore.requestCancellation).not.toHaveBeenCalled();
    });

    it('should throw error if job not found', async () => {
      // Arrange
      repository.findById.mockResolvedValue(null);

      // Act & Assert
      await expect(service.cancel('nonexistent-job')).rejects.toThrow(
        'Job not found: nonexistent-job',
      );

      expect(repository.updateJobStatus).not.toHaveBeenCalled();
      expect(cancellationStore.requestCancellation).not.toHaveBeenCalled();
    });
  });

  describe('getJob', () => {
    it('should return job by id', async () => {
      // Arrange
      const mockJob: Job = {
        id: 'job-123',
        type: JobType.WEBHOOK_DELIVERY,
        payload: { test: 'data' },
        status: JobStatus.PENDING,
        attempts: 0,
        maxAttempts: 5,
        createdAt: new Date(),
        scheduledAt: new Date(),
        startedAt: null,
        completedAt: null,
        failureReason: null,
        visibilityTimeout: null,
      };

      repository.findById.mockResolvedValue(mockJob);

      // Act
      const result = await service.getJob('job-123');

      // Assert
      expect(result).toBe(mockJob);
      expect(repository.findById).toHaveBeenCalledWith('job-123');
    });

    it('should return null if job not found', async () => {
      // Arrange
      repository.findById.mockResolvedValue(null);

      // Act
      const result = await service.getJob('nonexistent-job');

      // Assert
      expect(result).toBeNull();
      expect(repository.findById).toHaveBeenCalledWith('nonexistent-job');
    });
  });

  describe('listJobs', () => {
    it('should return paginated jobs with filters', async () => {
      // Arrange
      const mockJobs = {
        jobs: [
          {
            id: 'job-1',
            type: JobType.WEBHOOK_DELIVERY,
            payload: {},
            status: JobStatus.PENDING,
            attempts: 0,
            maxAttempts: 5,
            createdAt: new Date(),
            scheduledAt: new Date(),
            startedAt: null,
            completedAt: null,
            failureReason: null,
            visibilityTimeout: null,
          },
        ],
        total: 1,
        limit: 50,
        offset: 0,
      };

      repository.listJobs.mockResolvedValue(mockJobs);

      const filters = {
        type: JobType.WEBHOOK_DELIVERY,
        status: JobStatus.PENDING,
        limit: 50,
        offset: 0,
      };

      // Act
      const result = await service.listJobs(filters);

      // Assert
      expect(result).toBe(mockJobs);
      expect(repository.listJobs).toHaveBeenCalledWith(filters);
    });

    it('should call listJobs with empty filters when none provided', async () => {
      // Arrange
      const mockJobs = {
        jobs: [],
        total: 0,
        limit: 50,
        offset: 0,
      };

      repository.listJobs.mockResolvedValue(mockJobs);

      // Act
      const result = await service.listJobs();

      // Assert
      expect(result).toBe(mockJobs);
      expect(repository.listJobs).toHaveBeenCalledWith({});
    });
  });
});
