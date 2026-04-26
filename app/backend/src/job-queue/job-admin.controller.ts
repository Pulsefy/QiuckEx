/**
 * Job Queue System - Admin Controller
 * 
 * REST API endpoints for operators to monitor and manage jobs.
 * All endpoints require authentication and admin scope.
 * 
 * **Validates: Requirements 5.1, 5.2, 5.3, 5.4, 5.5, 6.1, 6.2, 6.3, 14.1, 14.2, 14.3, 14.4, 14.5**
 */

import {
  Controller,
  Get,
  Post,
  Param,
  Query,
  Body,
  UseGuards,
  ParseIntPipe,
  HttpCode,
  HttpStatus,
  NotFoundException,
  BadRequestException,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { JobQueueService } from './job-queue.service';
import { JobRepository, JobFilters } from './job.repository';
import { JobType, JobStatus, Job } from './types';
import { ApiKeyGuard } from '../auth/guards/api-key.guard';
import { RequireScopes } from '../auth/decorators/require-scopes.decorator';

/**
 * DTO for bulk retry request
 */
export class BulkRetryRequestDto {
  type: JobType;
  status?: JobStatus;
}

/**
 * DTO for bulk retry response
 */
export interface BulkRetryResponse {
  retriedCount: number;
  jobIds: string[];
}

/**
 * DTO for job metrics summary
 */
export interface JobMetrics {
  byType: Record<JobType, {
    pending: number;
    running: number;
    completed: number;
    failed: number;
    cancelled: number;
  }>;
  dlqCount: number;
}

/**
 * Admin controller for job queue management
 * 
 * Provides endpoints for:
 * - Listing and filtering jobs
 * - Viewing job details
 * - Cancelling jobs
 * - Retrying failed jobs (single and bulk)
 * - Viewing metrics and DLQ
 * 
 * All endpoints require authentication with admin scope.
 */
@ApiTags('Admin - Job Queue')
@Controller('admin/jobs')
@UseGuards(ApiKeyGuard)
@ApiBearerAuth()
export class JobAdminController {
  constructor(
    private readonly jobQueueService: JobQueueService,
    private readonly jobRepository: JobRepository,
  ) {}

  /**
   * List jobs with optional filters
   * 
   * Supports filtering by:
   * - Job type
   * - Job status
   * - Date range (createdAfter, createdBefore)
   * - Pagination (limit, offset)
   * 
   * **Validates: Requirements 5.1, 5.5**
   */
  @Get()
  @RequireScopes('admin')
  @ApiOperation({ summary: 'List jobs with filters' })
  @ApiResponse({ status: 200, description: 'Paginated job list' })
  async listJobs(
    @Query('type') type?: JobType,
    @Query('status') status?: JobStatus,
    @Query('createdAfter') createdAfter?: string,
    @Query('createdBefore') createdBefore?: string,
    @Query('limit', new ParseIntPipe({ optional: true })) limit?: number,
    @Query('offset', new ParseIntPipe({ optional: true })) offset?: number,
  ) {
    const filters: JobFilters = {
      type,
      status,
      createdAfter: createdAfter ? new Date(createdAfter) : undefined,
      createdBefore: createdBefore ? new Date(createdBefore) : undefined,
      limit,
      offset,
    };

    return this.jobQueueService.listJobs(filters);
  }

  /**
   * Get detailed information for a specific job
   * 
   * Returns full job details including payload and failure reason.
   * 
   * **Validates: Requirement 5.2**
   */
  @Get(':id')
  @RequireScopes('admin')
  @ApiOperation({ summary: 'Get job details by ID' })
  @ApiResponse({ status: 200, description: 'Job details' })
  @ApiResponse({ status: 404, description: 'Job not found' })
  async getJob(@Param('id') id: string): Promise<Job> {
    const job = await this.jobQueueService.getJob(id);

    if (!job) {
      throw new NotFoundException(`Job not found: ${id}`);
    }

    return job;
  }

  /**
   * Cancel a job by ID
   * 
   * For pending jobs: Updates status to 'cancelled' immediately
   * For running jobs: Sets a cancellation token that the handler can check
   * For completed/failed/cancelled jobs: No-op (already terminal state)
   * 
   * **Validates: Requirements 6.1, 6.2, 6.3**
   */
  @Post(':id/cancel')
  @RequireScopes('admin')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Cancel a job' })
  @ApiResponse({ status: 200, description: 'Job cancelled successfully' })
  @ApiResponse({ status: 404, description: 'Job not found' })
  async cancelJob(@Param('id') id: string): Promise<{ message: string }> {
    await this.jobQueueService.cancel(id);
    return { message: `Job ${id} cancellation requested` };
  }

  /**
   * Manually retry a failed job
   * 
   * Resets job status to pending, clears failureReason, and sets scheduledAt to now.
   * Rejects retry for completed or cancelled jobs.
   * Preserves original attempts count.
   * 
   * **Validates: Requirements 14.1, 14.2, 14.3, 14.4**
   */
  @Post(':id/retry')
  @RequireScopes('admin')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Manually retry a failed job' })
  @ApiResponse({ status: 200, description: 'Job retry scheduled' })
  @ApiResponse({ status: 400, description: 'Job cannot be retried' })
  @ApiResponse({ status: 404, description: 'Job not found' })
  async retryJob(@Param('id') id: string): Promise<{ message: string }> {
    const job = await this.jobQueueService.getJob(id);

    if (!job) {
      throw new NotFoundException(`Job not found: ${id}`);
    }

    // Requirement 14.3: Reject retry for completed or cancelled jobs
    if (job.status === JobStatus.COMPLETED || job.status === JobStatus.CANCELLED) {
      throw new BadRequestException(
        `Cannot retry job in ${job.status} status. Only failed or pending jobs can be retried.`,
      );
    }

    // Requirement 14.2: Reset status to pending, clear failureReason, set scheduledAt to now
    // Requirement 14.4: Preserve original attempts count
    await this.jobRepository.updateJobStatus(id, JobStatus.PENDING, {
      failureReason: null,
      scheduledAt: new Date(),
      // Note: attempts count is preserved (not reset)
    });

    return { message: `Job ${id} scheduled for retry` };
  }

  /**
   * Bulk retry jobs by type and status
   * 
   * Supports bulk retry for all jobs of a specific type in DLQ (failed status).
   * 
   * **Validates: Requirement 14.5**
   */
  @Post('bulk-retry')
  @RequireScopes('admin')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Bulk retry jobs by type' })
  @ApiResponse({ status: 200, description: 'Bulk retry completed' })
  async bulkRetry(@Body() request: BulkRetryRequestDto): Promise<BulkRetryResponse> {
    const filters: JobFilters = {
      type: request.type,
      status: request.status || JobStatus.FAILED,
      limit: 1000, // Limit bulk operations to prevent timeouts
    };

    const { jobs } = await this.jobQueueService.listJobs(filters);

    const retriedJobIds: string[] = [];

    for (const job of jobs) {
      // Only retry failed jobs (DLQ)
      if (job.status === JobStatus.FAILED) {
        await this.jobRepository.updateJobStatus(job.id, JobStatus.PENDING, {
          failureReason: null,
          scheduledAt: new Date(),
        });
        retriedJobIds.push(job.id);
      }
    }

    return {
      retriedCount: retriedJobIds.length,
      jobIds: retriedJobIds,
    };
  }

  /**
   * Get job metrics summary
   * 
   * Returns counts by job type and status:
   * - Pending, running, completed, failed, cancelled counts per type
   * - Total DLQ count
   * 
   * **Validates: Requirement 5.3**
   */
  @Get('metrics/summary')
  @RequireScopes('admin')
  @ApiOperation({ summary: 'Get job metrics summary' })
  @ApiResponse({ status: 200, description: 'Job metrics' })
  async getMetrics(): Promise<JobMetrics> {
    // Initialize metrics structure
    const byType: Record<string, {
      pending: number;
      running: number;
      completed: number;
      failed: number;
      cancelled: number;
    }> = {};

    // Initialize all job types
    for (const type of Object.values(JobType)) {
      byType[type] = {
        pending: 0,
        running: 0,
        completed: 0,
        failed: 0,
        cancelled: 0,
      };
    }

    // Query jobs for each type and status combination
    for (const type of Object.values(JobType)) {
      for (const status of Object.values(JobStatus)) {
        const { total } = await this.jobQueueService.listJobs({
          type,
          status,
          limit: 0, // Only get count, not actual jobs
        });

        byType[type][status] = total;
      }
    }

    // Count DLQ jobs (failed jobs that have exhausted retries)
    const allFailedJobs = await this.jobQueueService.listJobs({
      status: JobStatus.FAILED,
      limit: 10000, // Large limit to get all failed jobs
    });

    const dlqCount = allFailedJobs.jobs.filter(
      job => job.attempts >= job.maxAttempts,
    ).length;

    return {
      byType,
      dlqCount,
    };
  }

  /**
   * Get dead letter queue (DLQ) jobs
   * 
   * Returns jobs where status=failed AND attempts >= maxAttempts.
   * Supports pagination and filters.
   * 
   * **Validates: Requirement 5.4**
   */
  @Get('dlq')
  @RequireScopes('admin')
  @ApiOperation({ summary: 'Get dead letter queue jobs' })
  @ApiResponse({ status: 200, description: 'DLQ jobs' })
  async getDeadLetterQueue(
    @Query('type') type?: JobType,
    @Query('limit', new ParseIntPipe({ optional: true })) limit?: number,
    @Query('offset', new ParseIntPipe({ optional: true })) offset?: number,
  ) {
    const filters: JobFilters = {
      type,
      status: JobStatus.FAILED,
      limit,
      offset,
    };

    const result = await this.jobQueueService.listJobs(filters);

    // Filter to only include jobs that have exhausted retries (DLQ)
    const dlqJobs = result.jobs.filter(job => job.attempts >= job.maxAttempts);

    return {
      jobs: dlqJobs,
      total: dlqJobs.length,
      limit: result.limit,
      offset: result.offset,
    };
  }
}
