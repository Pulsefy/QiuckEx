import { ConflictException, NotFoundException } from '@nestjs/common';

import { AuditService } from '../../audit/audit.service';
import { BranchDeploymentRepository } from '../deployment-sync.repository';
import {
  BranchDeployment,
  SyncBranchDeploymentInput,
} from '../deployment-sync.model';
import { BranchDeploymentService } from '../deployment-sync.service';
import { SyncBranchDeploymentDto } from '../dto/sync-branch-deployment.dto';

const COMMIT_SHA = 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2';

function makeDeployment(overrides: Partial<BranchDeployment> = {}): BranchDeployment {
  return {
    id: 'deploy-1',
    branchName: 'feat/be-branch-metadata-sync',
    prNumber: 544,
    commitSha: COMMIT_SHA,
    previewUrl: 'https://preview-544.quickex.to',
    status: 'deployed',
    environment: 'preview',
    deliveredAt: new Date('2026-08-25T10:00:00.000Z'),
    createdAt: new Date('2026-08-25T10:00:00.000Z'),
    updatedAt: new Date('2026-08-25T10:00:00.000Z'),
    ...overrides,
  };
}

function makeDto(overrides: Partial<SyncBranchDeploymentDto> = {}): SyncBranchDeploymentDto {
  const dto = new SyncBranchDeploymentDto();
  dto.branchName = 'feat/be-branch-metadata-sync';
  dto.prNumber = 544;
  dto.commitSha = COMMIT_SHA;
  dto.previewUrl = 'https://preview-544.quickex.to';
  dto.status = 'deployed';
  dto.environment = 'preview';
  dto.deliveredAt = '2026-08-25T10:00:00.000Z';
  return Object.assign(dto, overrides) as SyncBranchDeploymentDto;
}

describe('BranchDeploymentService (BE-60)', () => {
  let service: BranchDeploymentService;
  let repository: {
    findLatestForBranch: jest.Mock;
    findByBranchAndCommit: jest.Mock;
    upsert: jest.Mock;
    findByPrNumber: jest.Mock;
  };
  let auditService: { log: jest.Mock };

  beforeEach(() => {
    repository = {
      findLatestForBranch: jest.fn().mockResolvedValue(null),
      findByBranchAndCommit: jest.fn().mockResolvedValue(null),
      upsert: jest.fn().mockImplementation((input: SyncBranchDeploymentInput) =>
        Promise.resolve(makeDeployment({ deliveredAt: input.deliveredAt })),
      ),
      findByPrNumber: jest.fn().mockResolvedValue([]),
    };
    auditService = { log: jest.fn().mockResolvedValue(undefined) };

    service = new BranchDeploymentService(
      repository as unknown as BranchDeploymentRepository,
      auditService as unknown as AuditService,
    );
  });

  describe('syncDeployment', () => {
    it('ingests a new deployment and writes an audit event', async () => {
      const result = await service.syncDeployment(makeDto(), 'api-key-1');

      expect(repository.upsert).toHaveBeenCalledWith(
        expect.objectContaining({
          branchName: 'feat/be-branch-metadata-sync',
          prNumber: 544,
          commitSha: COMMIT_SHA,
          status: 'deployed',
          environment: 'preview',
        }),
      );
      expect(result.id).toBe('deploy-1');
      expect(auditService.log).toHaveBeenCalledWith(
        'api-key-1',
        'branch_deployment.synced',
        'deploy-1',
        expect.objectContaining({ commitSha: COMMIT_SHA, branchName: 'feat/be-branch-metadata-sync' }),
      );
    });

    it('is idempotent for duplicate deliveries of the same (branch, commit)', async () => {
      const existing = makeDeployment();
      repository.findByBranchAndCommit.mockResolvedValue(existing);

      const result = await service.syncDeployment(
        makeDto({ deliveredAt: '2026-08-25T09:00:00.000Z' }),
        'github-webhook',
      );

      expect(result).toBe(existing);
      expect(repository.upsert).not.toHaveBeenCalled();
      expect(auditService.log).not.toHaveBeenCalled();
    });

    it('rejects stale out-of-order deliveries with a ConflictException', async () => {
      repository.findLatestForBranch.mockResolvedValue(
        makeDeployment({ deliveredAt: new Date('2026-08-25T11:00:00.000Z') }),
      );

      await expect(
        service.syncDeployment(makeDto({ deliveredAt: '2026-08-25T10:00:00.000Z' }), 'github-webhook'),
      ).rejects.toBeInstanceOf(ConflictException);

      expect(repository.upsert).not.toHaveBeenCalled();
    });

    it('normalizes branch names to lowercase', async () => {
      await service.syncDeployment(
        makeDto({ branchName: 'Feature/BE-Branch-Sync' }),
        'api-key-1',
      );

      expect(repository.upsert).toHaveBeenCalledWith(
        expect.objectContaining({ branchName: 'feature/be-branch-sync' }),
      );
    });

    it('defaults deliveredAt to now when omitted', async () => {
      const before = new Date().getTime();
      await service.syncDeployment(makeDto({ deliveredAt: undefined }), 'api-key-1');
      const after = new Date().getTime();

      const input = repository.upsert.mock.calls[0][0] as SyncBranchDeploymentInput;
      expect(input.deliveredAt.getTime()).toBeGreaterThanOrEqual(before);
      expect(input.deliveredAt.getTime()).toBeLessThanOrEqual(after);
    });

    it('updates a record when a newer delivery arrives for the same commit', async () => {
      const existing = makeDeployment({ deliveredAt: new Date('2026-08-25T09:00:00.000Z') });
      repository.findByBranchAndCommit.mockResolvedValue(existing);

      await service.syncDeployment(
        makeDto({ deliveredAt: '2026-08-25T10:00:00.000Z' }),
        'github-webhook',
      );

      expect(repository.upsert).toHaveBeenCalledWith(
        expect.objectContaining({
          deliveredAt: new Date('2026-08-25T10:00:00.000Z'),
          status: 'deployed',
        }),
      );
    });
  });

  describe('getDeploymentByBranch', () => {
    it('returns the latest deployment for a branch', async () => {
      const deployment = makeDeployment();
      repository.findLatestForBranch.mockResolvedValue(deployment);

      const result = await service.getDeploymentByBranch('feat/be-branch-metadata-sync');

      expect(result).toBe(deployment);
      expect(repository.findLatestForBranch).toHaveBeenCalledWith(
        'feat/be-branch-metadata-sync',
        undefined,
      );
    });

    it('scopes the lookup by PR number when provided', async () => {
      repository.findLatestForBranch.mockResolvedValue(makeDeployment());
      await service.getDeploymentByBranch('feat/be-branch-metadata-sync', 544);
      expect(repository.findLatestForBranch).toHaveBeenCalledWith(
        'feat/be-branch-metadata-sync',
        544,
      );
    });

    it('throws NotFoundException when nothing is recorded', async () => {
      await expect(
        service.getDeploymentByBranch('unknown-branch'),
      ).rejects.toBeInstanceOf(NotFoundException);
    });
  });

  describe('getDeploymentsByPr', () => {
    it('delegates to the repository with a default limit', async () => {
      repository.findByPrNumber.mockResolvedValue([makeDeployment()]);

      const result = await service.getDeploymentsByPr(544);

      expect(repository.findByPrNumber).toHaveBeenCalledWith(544, 20);
      expect(result).toHaveLength(1);
    });
  });
});
