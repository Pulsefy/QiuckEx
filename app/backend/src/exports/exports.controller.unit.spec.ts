import { Test, TestingModule } from '@nestjs/testing';
import { ExportsController } from './exports.controller';
import { JobQueueService } from '../job-queue/job-queue.service';
import { ExportsService } from './exports.service';
import { JobType } from '../job-queue/types';
import { ApiKeysService } from '../api-keys/api-keys.service';
import { Response, Request } from 'express';

describe('ExportsController', () => {
  let controller: ExportsController;
  let jobQueueService: JobQueueService;
  let exportsService: ExportsService;

  const mockJobQueueService = {
    enqueue: jest.fn(),
  };

  const mockExportsService = {
    verifyAndRetrieveArtifact: jest.fn(),
  };

  const mockApiKeysService = {};

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [ExportsController],
      providers: [
        {
          provide: JobQueueService,
          useValue: mockJobQueueService,
        },
        {
          provide: ExportsService,
          useValue: mockExportsService,
        },
        {
          provide: ApiKeysService,
          useValue: mockApiKeysService,
        },
      ],
    }).compile();

    controller = module.get<ExportsController>(ExportsController);
    jobQueueService = module.get<JobQueueService>(JobQueueService);
    exportsService = module.get<ExportsService>(ExportsService);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('requestExport', () => {
    it('should enqueue an export job and return job info', async () => {
      const dto = {
        userId: 'user-123',
        exportType: 'transactions' as const,
        format: 'csv' as const,
        deliveryMethod: 'download' as const,
        filters: { status: 'completed' },
      };

      mockJobQueueService.enqueue.mockResolvedValue('job-abc-123');

      const result = await controller.requestExport(dto);

      expect(result).toEqual({
        jobId: 'job-abc-123',
        message: 'Export job enqueued successfully. Job ID: job-abc-123',
      });
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
    });
  });

  describe('downloadExport', () => {
    it('should verify parameters and send downloaded file', async () => {
      const userId = 'user-123';
      const jobId = 'job-456';
      const format = 'csv';
      const expiresAt = '2026-08-24T14:00:00.000Z';
      const signature = 'valid-signature';

      const mockRequest = {
        apiKey: {
          owner_id: userId,
        },
      } as any;

      const mockResponse = {
        setHeader: jest.fn(),
        send: jest.fn(),
      } as any;

      mockExportsService.verifyAndRetrieveArtifact.mockResolvedValue({
        data: Buffer.from('col1,col2\nval1,val2'),
        contentType: 'text/csv',
      });

      await controller.downloadExport(
        userId,
        jobId,
        format,
        expiresAt,
        signature,
        mockRequest,
        mockResponse,
      );

      expect(exportsService.verifyAndRetrieveArtifact).toHaveBeenCalledWith(
        { userId, jobId, format, expiresAt, signature },
        userId,
      );
      expect(mockResponse.setHeader).toHaveBeenCalledWith('Content-Type', 'text/csv');
      expect(mockResponse.setHeader).toHaveBeenCalledWith(
        'Content-Disposition',
        `attachment; filename="export-${jobId}.${format}"`,
      );
      expect(mockResponse.send).toHaveBeenCalledWith(Buffer.from('col1,col2\nval1,val2'));
    });
  });
});
