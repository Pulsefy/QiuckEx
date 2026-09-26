import { BadRequestException, NotFoundException } from '@nestjs/common';
import { ExportsService } from './exports.service';
import { JobQueueService } from '../job-queue/job-queue.service';
import { ExportGenerationPayload } from '../job-queue/types/job-payloads.types';
import { Job, JobStatus, JobType } from '../job-queue/types';
import { RequestExportDto } from './dto/request-export.dto';

describe('ExportsService', () => {
  let service: ExportsService;
  let jobQueueService: jest.Mocked<Pick<JobQueueService, 'enqueue' | 'getJob'>>;

  const request: RequestExportDto = {
    userId: 'user-123',
    exportType: 'transactions',
    filters: { status: 'completed' },
    format: 'csv',
    deliveryMethod: 'download',
  };

  beforeEach(() => {
    jobQueueService = {
      enqueue: jest.fn(),
      getJob: jest.fn(),
    };
    service = new ExportsService(jobQueueService as unknown as JobQueueService);
  });

  it('validates and enqueues an export job', async () => {
    jobQueueService.enqueue.mockResolvedValue('export-123');

    await expect(service.requestExport(request)).resolves.toEqual({
      jobId: 'export-123',
      message: 'Export job enqueued successfully. Job ID: export-123',
    });
    expect(jobQueueService.enqueue).toHaveBeenCalledWith(JobType.EXPORT_GENERATION, {
      ...request,
      userId: 'user-123',
    });
  });

  it.each([
    [JobStatus.PENDING, 'queued'],
    [JobStatus.RUNNING, 'running'],
    [JobStatus.COMPLETED, 'completed'],
    [JobStatus.FAILED, 'failed'],
  ] as const)('maps job state %s to export state %s', async (jobStatus, expectedStatus) => {
    const createdAt = new Date('2026-01-01T00:00:00.000Z');
    const startedAt = jobStatus === JobStatus.PENDING ? null : new Date('2026-01-01T00:01:00.000Z');
    const completedAt = [JobStatus.COMPLETED, JobStatus.FAILED].includes(jobStatus)
      ? new Date('2026-01-01T00:02:00.000Z')
      : null;
    jobQueueService.getJob.mockResolvedValue({
      id: 'export-123',
      type: JobType.EXPORT_GENERATION,
      payload: request as ExportGenerationPayload,
      status: jobStatus,
      attempts: 0,
      maxAttempts: 2,
      createdAt,
      scheduledAt: createdAt,
      startedAt,
      completedAt,
      failureReason: jobStatus === JobStatus.FAILED ? 'generation failed' : null,
      visibilityTimeout: null,
    } as Job<ExportGenerationPayload>);

    const result = await service.getStatus('export-123');

    expect(result).toMatchObject({
      exportId: 'export-123',
      status: expectedStatus,
      createdAt: createdAt.toISOString(),
      startedAt: startedAt?.toISOString() ?? null,
      completedAt: completedAt?.toISOString() ?? null,
    });
    expect(result.deliveryReference).toBe(
      jobStatus === JobStatus.COMPLETED ? 'export-123' : undefined,
    );
    if (jobStatus === JobStatus.FAILED) {
      expect(result.failureReason).toBe('generation failed');
    }
  });

  it.each([
    { name: 'blank userId', value: { ...request, userId: '  ' } },
    { name: 'unsupported export type', value: { ...request, exportType: 'unknown' } },
    { name: 'unsupported format', value: { ...request, format: 'xml' } },
    { name: 'unsupported delivery method', value: { ...request, deliveryMethod: 'ftp' } },
    { name: 'array filters', value: { ...request, filters: ['not', 'an', 'object'] } },
    { name: 'nested filter value', value: { ...request, filters: { amount: { gte: 10 } } } },
  ])('rejects an invalid request: $name', async ({ value }) => {
    await expect(service.requestExport(value as RequestExportDto))
      .rejects.toBeInstanceOf(BadRequestException);
    expect(jobQueueService.enqueue).not.toHaveBeenCalled();
  });

  it('returns not found for missing or non-export jobs', async () => {
    jobQueueService.getJob.mockResolvedValue(null);

    await expect(service.getStatus('missing')).rejects.toBeInstanceOf(NotFoundException);
  });
});