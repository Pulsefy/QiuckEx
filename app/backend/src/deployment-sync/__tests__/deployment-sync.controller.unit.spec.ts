import { Test, TestingModule } from '@nestjs/testing';
import { NotFoundException } from '@nestjs/common';
import { DeploymentSyncController } from '../deployment-sync.controller';
import { DeploymentSyncService } from '../deployment-sync.service';
import { DeploymentWebhookPayloadDto } from '../dto/webhook-payload.dto';
import { DeploymentResponseDto } from '../dto/deployment-response.dto';
import { ApiKeyGuard } from '../../auth/guards/api-key.guard';

describe('DeploymentSyncController', () => {
  let controller: DeploymentSyncController;
  let service: jest.Mocked<DeploymentSyncService>;

  const mockResponse: DeploymentResponseDto = {
    id: 'uuid-123',
    branchName: 'feat/be-branch-metadata-sync',
    prNumber: 42,
    commitSha: 'a1b2c3d4e5f6g7h8i9j0a1b2c3d4e5f6g7h8i9j0',
    previewUrl: 'https://quickex-preview-pr-42.vercel.app',
    status: 'success',
    eventTimestamp: '2026-06-27T08:00:00.000Z',
    createdAt: '2026-06-27T08:00:05.000Z',
    updatedAt: '2026-06-27T08:00:05.000Z',
  };

  beforeEach(async () => {
    const mockSyncService = {
      syncDeployment: jest.fn().mockResolvedValue(mockResponse),
      getDeploymentByBranch: jest.fn().mockResolvedValue(mockResponse),
      getDeploymentsByPr: jest.fn().mockResolvedValue([mockResponse]),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [DeploymentSyncController],
      providers: [
        {
          provide: DeploymentSyncService,
          useValue: mockSyncService,
        },
      ],
    })
      .overrideGuard(ApiKeyGuard)
      .useValue({ canActivate: () => true })
      .compile();

    controller = module.get<DeploymentSyncController>(DeploymentSyncController);
    service = module.get(DeploymentSyncService) as jest.Mocked<DeploymentSyncService>;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('syncDeployment', () => {
    it('should call service.syncDeployment and return the result', async () => {
      const payload: DeploymentWebhookPayloadDto = {
        branchName: 'feat/be-branch-metadata-sync',
        prNumber: 42,
        commitSha: 'a1b2c3d4e5f6g7h8i9j0a1b2c3d4e5f6g7h8i9j0',
        previewUrl: 'https://quickex-preview-pr-42.vercel.app',
        status: 'success',
        eventTimestamp: '2026-06-27T08:00:00.000Z',
      };

      const result = await controller.syncDeployment(payload);

      expect(service.syncDeployment).toHaveBeenCalledWith(payload);
      expect(result).toEqual(mockResponse);
    });
  });

  describe('getDeploymentByBranch', () => {
    it('should call service.getDeploymentByBranch and return the result', async () => {
      const result = await controller.getDeploymentByBranch('feat/be-branch-metadata-sync');

      expect(service.getDeploymentByBranch).toHaveBeenCalledWith('feat/be-branch-metadata-sync');
      expect(result).toEqual(mockResponse);
    });

    it('should propagate service NotFoundException', async () => {
      service.getDeploymentByBranch.mockRejectedValueOnce(new NotFoundException('Not found'));

      await expect(controller.getDeploymentByBranch('non-existent')).rejects.toThrow(NotFoundException);
    });
  });

  describe('getDeploymentsByPr', () => {
    it('should call service.getDeploymentsByPr and return the result', async () => {
      const result = await controller.getDeploymentsByPr(42);

      expect(service.getDeploymentsByPr).toHaveBeenCalledWith(42);
      expect(result).toEqual([mockResponse]);
    });

    it('should propagate service NotFoundException', async () => {
      service.getDeploymentsByPr.mockRejectedValueOnce(new NotFoundException('Not found'));

      await expect(controller.getDeploymentsByPr(999)).rejects.toThrow(NotFoundException);
    });
  });
});
