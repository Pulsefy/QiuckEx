import { Test, TestingModule } from '@nestjs/testing';
import { BadRequestException, NotFoundException } from '@nestjs/common';
import { ExportsService } from '../exports.service';
import { ExportRepository } from '../export.repository';
import { JobQueueService, PayloadValidationError } from '../../job-queue/job-queue.service';
import { JobType } from '../../job-queue/types';
import { RequestExportDto } from '../dto/request-export.dto';
import {
  ExportDeliveryMethod,
  ExportFormat,
  ExportStatus,
  ExportType,
} from '../enums/export.enums';
import { ExportRecord } from '../types/export.types';
import { EXPORT_ENQUEUED_MESSAGE } from '../constants/export.constants';

function makeDto(
  overrides: Partial<RequestExportDto> = {},
): RequestExportDto {
  return {
    userId: 'GUSER123',
    exportType: ExportType.TRANSACTIONS,
    format: ExportFormat.CSV,
    deliveryMethod: ExportDeliveryMethod.EMAIL,
    filters: { status: 'completed' },
    ...overrides,
  };
}

function makeRecord(overrides: Partial<ExportRecord> = {}): ExportRecord {
  const now = new Date('2026-08-28T12:00:00.000Z');
  return {
    id: 'rec-1',
    jobId: 'job-1',
    userId: 'GUSER123',
    exportType: ExportType.TRANSACTIONS,
    format: ExportFormat.CSV,
    deliveryMethod: ExportDeliveryMethod.EMAIL,
    filters: {},
    status: ExportStatus.QUEUED,
    deliveryReference: null,
    failureReason: null,
    queuedAt: now,
    startedAt: null,
    completedAt: null,
    failedAt: null,
    createdAt: now,
    updatedAt: now,
    ...overrides,
  };
}

describe('ExportsService', () => {
  let service: ExportsService;
  let jobQueueService: jest.Mocked<Pick<JobQueueService, 'enqueue' | 'cancel'>>;
  let exportRepository: jest.Mocked<
    Pick<ExportRepository, 'create' | 'findByJobId' | 'transition'>
  >;

  beforeEach(async () => {
    jobQueueService = {
      enqueue: jest.fn().mockResolvedValue('job-1'),
      cancel: jest.fn().mockResolvedValue(undefined),
    };

    exportRepository = {
      create: jest.fn().mockResolvedValue(makeRecord()),
      findByJobId: jest.fn(),
      transition: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ExportsService,
        { provide: JobQueueService, useValue: jobQueueService },
        { provide: ExportRepository, useValue: exportRepository },
      ],
    }).compile();

    service = module.get(ExportsService);
  });

  describe('requestExport – enqueue', () => {
    it('validates, enqueues an export_generation job, and persists a queued record', async () => {
      const dto = makeDto();

      const result = await service.requestExport(dto);

      expect(jobQueueService.enqueue).toHaveBeenCalledWith(
        JobType.EXPORT_GENERATION,
        {
          userId: dto.userId,
          exportType: dto.exportType,
          filters: dto.filters,
          format: dto.format,
          deliveryMethod: dto.deliveryMethod,
        },
      );
      expect(exportRepository.create).toHaveBeenCalledWith({
        jobId: 'job-1',
        userId: dto.userId,
        exportType: dto.exportType,
        format: dto.format,
        deliveryMethod: dto.deliveryMethod,
        filters: dto.filters,
      });
      expect(result).toEqual({
        jobId: 'job-1',
        status: ExportStatus.QUEUED,
        message: `${EXPORT_ENQUEUED_MESSAGE}. Job ID: job-1`,
      });
    });

    it('defaults missing filters to an empty object', async () => {
      await service.requestExport(makeDto({ filters: undefined }));

      expect(jobQueueService.enqueue).toHaveBeenCalledWith(
        JobType.EXPORT_GENERATION,
        expect.objectContaining({ filters: {} }),
      );
      expect(exportRepository.create).toHaveBeenCalledWith(
        expect.objectContaining({ filters: {} }),
      );
    });

    it('cancels the job when persist fails after enqueue', async () => {
      exportRepository.create.mockRejectedValue(new Error('db down'));

      await expect(service.requestExport(makeDto())).rejects.toThrow('db down');
      expect(jobQueueService.cancel).toHaveBeenCalledWith('job-1');
    });

    it('maps payload validation failures to BadRequestException', async () => {
      jobQueueService.enqueue.mockRejectedValue(
        new PayloadValidationError('exportType is required'),
      );

      await expect(service.requestExport(makeDto())).rejects.toThrow(
        BadRequestException,
      );
      expect(exportRepository.create).not.toHaveBeenCalled();
    });
  });

  describe('requestExport – rejection of invalid requests', () => {
    it('rejects a missing userId', async () => {
      await expect(
        service.requestExport(makeDto({ userId: '' })),
      ).rejects.toThrow(BadRequestException);

      expect(jobQueueService.enqueue).not.toHaveBeenCalled();
    });

    it('rejects an invalid export type', async () => {
      await expect(
        service.requestExport(
          makeDto({ exportType: 'invoices' as ExportType }),
        ),
      ).rejects.toThrow(/exportType/);

      expect(jobQueueService.enqueue).not.toHaveBeenCalled();
    });

    it('rejects an invalid format', async () => {
      await expect(
        service.requestExport(makeDto({ format: 'xml' as ExportFormat })),
      ).rejects.toThrow(/format/);

      expect(jobQueueService.enqueue).not.toHaveBeenCalled();
    });

    it('rejects an invalid delivery method', async () => {
      await expect(
        service.requestExport(
          makeDto({ deliveryMethod: 'fax' as ExportDeliveryMethod }),
        ),
      ).rejects.toThrow(/deliveryMethod/);

      expect(jobQueueService.enqueue).not.toHaveBeenCalled();
    });

    it('rejects filters that are not a plain object', async () => {
      await expect(
        service.requestExport(
          makeDto({ filters: ['not-an-object'] as unknown as Record<string, unknown> }),
        ),
      ).rejects.toThrow(/filters/);

      expect(jobQueueService.enqueue).not.toHaveBeenCalled();
    });
  });

  describe('getStatus', () => {
    it('returns the current state for a queued export without a delivery reference', async () => {
      exportRepository.findByJobId.mockResolvedValue(makeRecord());

      const view = await service.getStatus('job-1');

      expect(view.status).toBe(ExportStatus.QUEUED);
      expect(view.jobId).toBe('job-1');
      expect(view.deliveryReference).toBeUndefined();
      expect(view.queuedAt).toBe('2026-08-28T12:00:00.000Z');
    });

    it('includes the delivery reference when the export is completed', async () => {
      exportRepository.findByJobId.mockResolvedValue(
        makeRecord({
          status: ExportStatus.COMPLETED,
          deliveryReference: 'email:export:job-1',
          completedAt: new Date('2026-08-28T12:05:00.000Z'),
        }),
      );

      const view = await service.getStatus('job-1');

      expect(view.status).toBe(ExportStatus.COMPLETED);
      expect(view.deliveryReference).toBe('email:export:job-1');
      expect(view.completedAt).toBe('2026-08-28T12:05:00.000Z');
    });

    it('throws NotFoundException when the export record does not exist', async () => {
      exportRepository.findByJobId.mockResolvedValue(null);

      await expect(service.getStatus('missing')).rejects.toThrow(
        NotFoundException,
      );
    });
  });

  describe('status transitions', () => {
    it('marks an export as running', async () => {
      const running = makeRecord({ status: ExportStatus.RUNNING });
      exportRepository.transition.mockResolvedValue(running);

      const result = await service.markRunning('job-1');

      expect(exportRepository.transition).toHaveBeenCalledWith(
        'job-1',
        ExportStatus.RUNNING,
      );
      expect(result.status).toBe(ExportStatus.RUNNING);
    });

    it('marks an export as completed with a delivery reference', async () => {
      const completed = makeRecord({
        status: ExportStatus.COMPLETED,
        deliveryReference: 'exports/GUSER123/job-1.csv',
      });
      exportRepository.transition.mockResolvedValue(completed);

      const result = await service.markCompleted(
        'job-1',
        'exports/GUSER123/job-1.csv',
      );

      expect(exportRepository.transition).toHaveBeenCalledWith(
        'job-1',
        ExportStatus.COMPLETED,
        { deliveryReference: 'exports/GUSER123/job-1.csv' },
      );
      expect(result.status).toBe(ExportStatus.COMPLETED);
      expect(result.deliveryReference).toBe('exports/GUSER123/job-1.csv');
    });

    it('marks an export as failed with a reason', async () => {
      const failed = makeRecord({
        status: ExportStatus.FAILED,
        failureReason: 'database connection refused',
      });
      exportRepository.transition.mockResolvedValue(failed);

      const result = await service.markFailed(
        'job-1',
        'database connection refused',
      );

      expect(exportRepository.transition).toHaveBeenCalledWith(
        'job-1',
        ExportStatus.FAILED,
        { failureReason: 'database connection refused' },
      );
      expect(result.status).toBe(ExportStatus.FAILED);
    });
  });
});
