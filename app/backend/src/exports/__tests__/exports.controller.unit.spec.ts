import { Test, TestingModule } from '@nestjs/testing';
import { NotFoundException } from '@nestjs/common';
import { ExportsController } from '../exports.controller';
import { ExportsService } from '../exports.service';
import { ExportStorageService } from '../export-storage.service';
import { RequestExportDto } from '../dto/request-export.dto';
import { ApiKeyGuard } from '../../auth/guards/api-key.guard';
import {
  ExportDeliveryMethod,
  ExportFormat,
  ExportStatus,
  ExportType,
} from '../enums/export.enums';

describe('ExportsController', () => {
  let controller: ExportsController;
  let exportsService: jest.Mocked<Pick<ExportsService, 'requestExport' | 'getStatus'>>;

  beforeEach(async () => {
    exportsService = {
      requestExport: jest.fn(),
      getStatus: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [ExportsController],
      providers: [
        { provide: ExportsService, useValue: exportsService },
        {
          provide: ExportStorageService,
          useValue: {
            verifyDownloadToken: jest.fn(),
            findArtifactRecord: jest.fn(),
            createPresignedDownloadUrl: jest.fn(),
          },
        },
      ],
    })
      .overrideGuard(ApiKeyGuard)
      .useValue({ canActivate: () => true })
      .compile();

    controller = module.get(ExportsController);
  });

  it('delegates export requests to ExportsService', async () => {
    const dto: RequestExportDto = {
      userId: 'GUSER123',
      exportType: ExportType.TRANSACTIONS,
      format: ExportFormat.CSV,
      deliveryMethod: ExportDeliveryMethod.EMAIL,
    };
    const enqueued = {
      jobId: 'job-1',
      status: ExportStatus.QUEUED,
      message: 'Export job enqueued successfully. Job ID: job-1',
    };
    exportsService.requestExport.mockResolvedValue(enqueued);

    await expect(controller.requestExport(dto)).resolves.toEqual(enqueued);
    expect(exportsService.requestExport).toHaveBeenCalledWith(dto);
  });

  it('delegates status lookup to ExportsService', async () => {
    const status = {
      jobId: 'job-1',
      status: ExportStatus.COMPLETED,
      exportType: ExportType.TRANSACTIONS,
      format: ExportFormat.CSV,
      deliveryMethod: ExportDeliveryMethod.EMAIL,
      queuedAt: '2026-08-28T12:00:00.000Z',
      startedAt: '2026-08-28T12:01:00.000Z',
      completedAt: '2026-08-28T12:02:00.000Z',
      failedAt: null,
      deliveryReference: 'email:export:job-1',
    };
    exportsService.getStatus.mockResolvedValue(status);

    await expect(controller.getExportStatus('job-1')).resolves.toEqual(status);
    expect(exportsService.getStatus).toHaveBeenCalledWith('job-1');
  });

  it('surfaces NotFoundException from status lookup', async () => {
    exportsService.getStatus.mockRejectedValue(
      new NotFoundException('Export job not found: missing'),
    );

    await expect(controller.getExportStatus('missing')).rejects.toThrow(
      NotFoundException,
    );
  });
});
