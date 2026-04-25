/**
 * Job Repository - Basic Verification Tests
 * 
 * These tests verify the JobRepository implementation against the requirements.
 * Full unit tests will be implemented in task 1.4.
 */

import { Test, TestingModule } from '@nestjs/testing';
import { JobRepository } from './job.repository';
import { SupabaseService } from '../supabase/supabase.service';
import { JobType, JobStatus } from './types/job.types';

describe('JobRepository - Basic Verification', () => {
  let repository: JobRepository;
  let supabaseService: SupabaseService;

  // Mock Supabase client
  const mockSupabaseClient = {
    from: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        JobRepository,
        {
          provide: SupabaseService,
          useValue: {
            getClient: jest.fn(() => mockSupabaseClient),
          },
        },
      ],
    }).compile();

    repository = module.get<JobRepository>(JobRepository);
    supabaseService = module.get<SupabaseService>(SupabaseService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('createJob', () => {
    it('should create a job with correct defaults', async () => {
      const mockJobRow = {
        id: 'test-job-id',
        type: JobType.WEBHOOK_DELIVERY,
        payload: { test: 'data' },
        status: JobStatus.PENDING,
        attempts: 0,
        max_attempts: 5,
        created_at: new Date().toISOString(),
        scheduled_at: new Date().toISOString(),
        started_at: null,
        completed_at: null,
        failure_reason: null,
        visibility_timeout: null,
      };

      const mockInsert = jest.fn().mockReturnValue({
        select: jest.fn().mockReturnValue({
          single: jest.fn().mockResolvedValue({
            data: mockJobRow,
            error: null,
          }),
        }),
      });

      mockSupabaseClient.from.mockReturnValue({
        insert: mockInsert,
      });

      const result = await repository.createJob(
        JobType.WEBHOOK_DELIVERY,
        { test: 'data' },
        5,
      );

      expect(result.id).toBe('test-job-id');
      expect(result.type).toBe(JobType.WEBHOOK_DELIVERY);
      expect(result.status).toBe(JobStatus.PENDING);
      expect(result.attempts).toBe(0);
      expect(result.maxAttempts).toBe(5);
      expect(mockSupabaseClient.from).toHaveBeenCalledWith('jobs');
      expect(mockInsert).toHaveBeenCalledWith(
        expect.objectContaining({
          type: JobType.WEBHOOK_DELIVERY,
          payload: { test: 'data' },
          status: JobStatus.PENDING,
          attempts: 0,
          max_attempts: 5,
        }),
      );
    });
  });

  describe('updateJobStatus', () => {
    it('should update job status with additional fields', async () => {
      const mockUpdate = jest.fn().mockReturnValue({
        eq: jest.fn().mockResolvedValue({
          data: null,
          error: null,
        }),
      });

      mockSupabaseClient.from.mockReturnValue({
        update: mockUpdate,
      });

      const now = new Date();
      await repository.updateJobStatus('test-job-id', JobStatus.RUNNING, {
        attempts: 1,
        startedAt: now,
        visibilityTimeout: new Date(now.getTime() + 300000),
      });

      expect(mockSupabaseClient.from).toHaveBeenCalledWith('jobs');
      expect(mockUpdate).toHaveBeenCalledWith(
        expect.objectContaining({
          status: JobStatus.RUNNING,
          attempts: 1,
          started_at: now.toISOString(),
        }),
      );
    });
  });

  describe('findDueJobs', () => {
    it('should query for pending jobs with expired visibility timeout', async () => {
      const mockSelect = jest.fn().mockReturnValue({
        eq: jest.fn().mockReturnValue({
          lte: jest.fn().mockReturnValue({
            or: jest.fn().mockReturnValue({
              order: jest.fn().mockReturnValue({
                limit: jest.fn().mockResolvedValue({
                  data: [],
                  error: null,
                }),
              }),
            }),
          }),
        }),
      });

      mockSupabaseClient.from.mockReturnValue({
        select: mockSelect,
      });

      await repository.findDueJobs(100);

      expect(mockSupabaseClient.from).toHaveBeenCalledWith('jobs');
      expect(mockSelect).toHaveBeenCalledWith('*');
    });
  });

  describe('findById', () => {
    it('should return null when job not found', async () => {
      const mockSelect = jest.fn().mockReturnValue({
        eq: jest.fn().mockReturnValue({
          maybeSingle: jest.fn().mockResolvedValue({
            data: null,
            error: { code: 'PGRST116' },
          }),
        }),
      });

      mockSupabaseClient.from.mockReturnValue({
        select: mockSelect,
      });

      const result = await repository.findById('non-existent-id');

      expect(result).toBeNull();
    });

    it('should return job when found', async () => {
      const mockJobRow = {
        id: 'test-job-id',
        type: JobType.WEBHOOK_DELIVERY,
        payload: { test: 'data' },
        status: JobStatus.PENDING,
        attempts: 0,
        max_attempts: 5,
        created_at: new Date().toISOString(),
        scheduled_at: new Date().toISOString(),
        started_at: null,
        completed_at: null,
        failure_reason: null,
        visibility_timeout: null,
      };

      const mockSelect = jest.fn().mockReturnValue({
        eq: jest.fn().mockReturnValue({
          maybeSingle: jest.fn().mockResolvedValue({
            data: mockJobRow,
            error: null,
          }),
        }),
      });

      mockSupabaseClient.from.mockReturnValue({
        select: mockSelect,
      });

      const result = await repository.findById('test-job-id');

      expect(result).not.toBeNull();
      expect(result?.id).toBe('test-job-id');
    });
  });

  describe('listJobs', () => {
    it('should apply filters and pagination', async () => {
      const mockSelect = jest.fn().mockReturnValue({
        eq: jest.fn().mockReturnThis(),
        gte: jest.fn().mockReturnThis(),
        lte: jest.fn().mockReturnThis(),
        order: jest.fn().mockReturnThis(),
        range: jest.fn().mockResolvedValue({
          data: [],
          error: null,
          count: 0,
        }),
      });

      mockSupabaseClient.from.mockReturnValue({
        select: mockSelect,
      });

      const result = await repository.listJobs({
        type: JobType.WEBHOOK_DELIVERY,
        status: JobStatus.PENDING,
        limit: 10,
        offset: 0,
      });

      expect(result.jobs).toEqual([]);
      expect(result.total).toBe(0);
      expect(result.limit).toBe(10);
      expect(result.offset).toBe(0);
    });
  });

  describe('resetStaleJobs', () => {
    it('should reset running jobs to pending', async () => {
      const mockUpdate = jest.fn().mockReturnValue({
        eq: jest.fn().mockReturnValue({
          select: jest.fn().mockResolvedValue({
            data: [{ id: 'job1' }, { id: 'job2' }],
            error: null,
          }),
        }),
      });

      mockSupabaseClient.from.mockReturnValue({
        update: mockUpdate,
      });

      const count = await repository.resetStaleJobs();

      expect(count).toBe(2);
      expect(mockSupabaseClient.from).toHaveBeenCalledWith('jobs');
      expect(mockUpdate).toHaveBeenCalledWith({
        status: JobStatus.PENDING,
        visibility_timeout: null,
      });
    });
  });
});
