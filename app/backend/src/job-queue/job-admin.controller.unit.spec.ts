/**
 * Job Admin Controller - Integration Tests
 * 
 * Tests the admin API endpoints for job monitoring and management.
 */

import { Test, TestingModule } from '@nestjs/testing';
import { NotFoundException, BadRequestException } from '@nestjs/common';
import { JobAdminController } from './job-admin.controller';
import { JobQueueService } from './job-queue.service';
import { JobRepository } from './job.repository';
import { JobType, JobStatus, Job } from './types';
import { ApiKeyGuard } from '../auth/guards/api-key.guard';

describe('JobAdminController', () => {
  let controller: JobAdminController;
  let jobQueueService: jest.Mocked<JobQueueService>;
  let jobRepository: jest.Mocked<JobRepository>;

  beforeEach(async () => {
    const mockJobQueueService = {
      listJobs: jest.fn(),
      getJob: jest.fn(),
      cancel: jest.fn(),
    };

    const mockJobRepository = {
      updateJobStatus: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [JobAdminController],
      providers: [
        {
          provide: JobQueueService,
          useValue: mockJobQueueService,
        },
        {
          provide: JobRepository,
          useValue: mockJobRepository,
        },
      ],
    })
      .overrideGuard(ApiKeyGuard)
      .useValue({ canActivate: () => true })
      .compile();

    controller = module.get<JobAdminController>(JobAdminController);
    jobQueueService = module.get(JobQueueService);
    jobRepository = module.get(JobRepository);
  });

  describe('listJobs', () => {
    it('should list jobs with filters', async () => {
      const mockResult = {
        jobs: [],
        total: 0,
        limit: 50,
        offset: 0,
      };

      jobQueueService.listJobs.mockResolvedValue(mockResult);

      const result = await controller.listJobs(
        JobType.WEBHOOK_DELIVERY,
        JobStatus.PENDING,
        undefined,
        undefined,
        10,
        0,
      );

      expect(result).toEqual(mockResult);
      expect(jobQueueService.listJobs).toHaveBeenCalledWith({
        type: JobType.WEBHOOK_DELIVERY,
        status: JobStatus.PENDING,
        createdAfter: undefined,
        createdBefore: undefined,
        limit: 10,
        offset: 0,
      });
    });
  });

  describe('getJob', () => {
    it('should return job details', async () => {
      const mockJob: Job = {
        id: 'job-1',
        type: JobType.WEBHOOK_DELIVERY,
        payload: { test: 'data' },
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

      jobQueueService.getJob.mockResolvedValue(mockJob);

      const result = await controller.getJob('job-1');

      expect(result).toEqual(mockJob);
      expect(jobQueueService.getJob).toHaveBeenCalledWith('job-1');
    });

    it('should throw NotFoundException if job not found', async () => {
      jobQueueService.getJob.mockResolvedValue(null);

      await expect(controller.getJob('nonexistent')).rejects.toThrow(
        NotFoundException,
      );
    });
  });

  describe('cancelJob', () => {
    it('should cancel a job', async () => {
      jobQueueService.cancel.mockResolvedValue(undefined);

      const result = await controller.cancelJob('job-1');

      expect(result).toEqual({ message: 'Job job-1 cancellation requested' });
      expect(jobQueueService.cancel).toHaveBeenCalledWith('job-1');
    });
  });

  describe('retryJob', () => {
    it('should retry a failed job', async () => {
      const mockJob: Job = {
        id: 'job-1',
        type: JobType.WEBHOOK_DELIVERY,
        payload: { test: 'data' },
        status: JobStatus.FAILED,
        attempts: 3,
        maxAttempts: 3,
        createdAt: new Date(),
        scheduledAt: new Date(),
        startedAt: new Date(),
        completedAt: null,
        failureReason: 'Network error',
        visibilityTimeout: null,
      };

      jobQueueService.getJob.mockResolvedValue(mockJob);
      jobRepository.updateJobStatus.mockResolvedValue(undefined);

      const result = await controller.retryJob('job-1');

      expect(result).toEqual({ message: 'Job job-1 scheduled for retry' });
      expect(jobRepository.updateJobStatus).toHaveBeenCalledWith(
        'job-1',
        JobStatus.PENDING,
        {
          failureReason: null,
          scheduledAt: expect.any(Date),
        },
      );
    });

    it('should throw NotFoundException if job not found', async () => {
      jobQueueService.getJob.mockResolvedValue(null);

      await expect(controller.retryJob('nonexistent')).rejects.toThrow(
        NotFoundException,
      );
    });

    it('should throw BadRequestException for completed jobs', async () => {
      const mockJob: Job = {
        id: 'job-1',
        type: JobType.WEBHOOK_DELIVERY,
        payload: { test: 'data' },
        status: JobStatus.COMPLETED,
        attempts: 1,
        maxAttempts: 3,
        createdAt: new Date(),
        scheduledAt: new Date(),
        startedAt: new Date(),
        completedAt: new Date(),
        failureReason: null,
        visibilityTimeout: null,
      };

      jobQueueService.getJob.mockResolvedValue(mockJob);

      await expect(controller.retryJob('job-1')).rejects.toThrow(
        BadRequestException,
      );
    });

    it('should throw BadRequestException for cancelled jobs', async () => {
      const mockJob: Job = {
        id: 'job-1',
        type: JobType.WEBHOOK_DELIVERY,
        payload: { test: 'data' },
        status: JobStatus.CANCELLED,
        attempts: 0,
        maxAttempts: 3,
        createdAt: new Date(),
        scheduledAt: new Date(),
        startedAt: null,
        completedAt: new Date(),
        failureReason: null,
        visibilityTimeout: null,
      };

      jobQueueService.getJob.mockResolvedValue(mockJob);

      await expect(controller.retryJob('job-1')).rejects.toThrow(
        BadRequestException,
      );
    });
  });

  describe('bulkRetry', () => {
    it('should bulk retry failed jobs', async () => {
      const mockJobs: Job[] = [
        {
          id: 'job-1',
          type: JobType.WEBHOOK_DELIVERY,
          payload: {},
          status: JobStatus.FAILED,
          attempts: 3,
          maxAttempts: 3,
          createdAt: new Date(),
          scheduledAt: new Date(),
          startedAt: null,
          completedAt: null,
          failureReason: 'Error 1',
          visibilityTimeout: null,
        },
        {
          id: 'job-2',
          type: JobType.WEBHOOK_DELIVERY,
          payload: {},
          status: JobStatus.FAILED,
          attempts: 3,
          maxAttempts: 3,
          createdAt: new Date(),
          scheduledAt: new Date(),
          startedAt: null,
          completedAt: null,
          failureReason: 'Error 2',
          visibilityTimeout: null,
        },
      ];

      jobQueueService.listJobs.mockResolvedValue({
        jobs: mockJobs,
        total: 2,
        limit: 1000,
        offset: 0,
      });

      jobRepository.updateJobStatus.mockResolvedValue(undefined);

      const result = await controller.bulkRetry({
        type: JobType.WEBHOOK_DELIVERY,
      });

      expect(result.retriedCount).toBe(2);
      expect(result.jobIds).toEqual(['job-1', 'job-2']);
      expect(jobRepository.updateJobStatus).toHaveBeenCalledTimes(2);
    });
  });

  describe('getMetrics', () => {
    it('should return job metrics summary', async () => {
      // Mock listJobs to return counts for different statuses
      jobQueueService.listJobs.mockImplementation(async (filters) => {
        // Return different counts based on status
        const counts: Record<string, number> = {
          pending: 5,
          running: 2,
          completed: 100,
          failed: 3,
          cancelled: 1,
        };

        return {
          jobs: [],
          total: counts[filters.status || 'pending'] || 0,
          limit: 0,
          offset: 0,
        };
      });

      const result = await controller.getMetrics();

      expect(result).toHaveProperty('byType');
      expect(result).toHaveProperty('dlqCount');
      expect(result.byType[JobType.WEBHOOK_DELIVERY]).toHaveProperty('pending');
      expect(result.byType[JobType.WEBHOOK_DELIVERY]).toHaveProperty('running');
      expect(result.byType[JobType.WEBHOOK_DELIVERY]).toHaveProperty('completed');
      expect(result.byType[JobType.WEBHOOK_DELIVERY]).toHaveProperty('failed');
      expect(result.byType[JobType.WEBHOOK_DELIVERY]).toHaveProperty('cancelled');
    });
  });

  describe('getDeadLetterQueue', () => {
    it('should return DLQ jobs', async () => {
      const mockDLQJobs: Job[] = [
        {
          id: 'job-1',
          type: JobType.WEBHOOK_DELIVERY,
          payload: {},
          status: JobStatus.FAILED,
          attempts: 3,
          maxAttempts: 3,
          createdAt: new Date(),
          scheduledAt: new Date(),
          startedAt: null,
          completedAt: null,
          failureReason: 'Exhausted retries',
          visibilityTimeout: null,
        },
      ];

      jobQueueService.listJobs.mockResolvedValue({
        jobs: mockDLQJobs,
        total: 1,
        limit: 50,
        offset: 0,
      });

      const result = await controller.getDeadLetterQueue(
        JobType.WEBHOOK_DELIVERY,
        50,
        0,
      );

      expect(result.jobs).toHaveLength(1);
      expect(result.jobs[0].attempts).toBeGreaterThanOrEqual(
        result.jobs[0].maxAttempts,
      );
    });

    it('should filter out jobs that have not exhausted retries', async () => {
      const mockJobs: Job[] = [
        {
          id: 'job-1',
          type: JobType.WEBHOOK_DELIVERY,
          payload: {},
          status: JobStatus.FAILED,
          attempts: 3,
          maxAttempts: 3,
          createdAt: new Date(),
          scheduledAt: new Date(),
          startedAt: null,
          completedAt: null,
          failureReason: 'Exhausted retries',
          visibilityTimeout: null,
        },
        {
          id: 'job-2',
          type: JobType.WEBHOOK_DELIVERY,
          payload: {},
          status: JobStatus.FAILED,
          attempts: 1,
          maxAttempts: 3,
          createdAt: new Date(),
          scheduledAt: new Date(),
          startedAt: null,
          completedAt: null,
          failureReason: 'Will retry',
          visibilityTimeout: null,
        },
      ];

      jobQueueService.listJobs.mockResolvedValue({
        jobs: mockJobs,
        total: 2,
        limit: 50,
        offset: 0,
      });

      const result = await controller.getDeadLetterQueue(
        JobType.WEBHOOK_DELIVERY,
        50,
        0,
      );

      expect(result.jobs).toHaveLength(1);
      expect(result.jobs[0].id).toBe('job-1');
    });
  });
});
