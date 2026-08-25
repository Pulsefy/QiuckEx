import { createHmac } from 'crypto';
import {
  BadRequestException,
  ServiceUnavailableException,
  UnauthorizedException,
} from '@nestjs/common';
import type { RawBodyRequest, Request } from 'express';

import { AppConfigService } from '../../config/app-config.service';
import { BranchDeploymentService } from '../deployment-sync.service';
import { BranchDeploymentController } from '../deployment-sync.controller';
import { BranchDeployment } from '../deployment-sync.model';
import { SyncBranchDeploymentDto } from '../dto/sync-branch-deployment.dto';

const SECRET = 'test-webhook-secret';
const COMMIT_SHA = 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2';

function sign(payload: unknown): { rawBody: Buffer; signature: string } {
  const rawBody = Buffer.from(JSON.stringify(payload));
  const signature = `sha256=${createHmac('sha256', SECRET).update(rawBody).digest('hex')}`;
  return { rawBody, signature };
}

function makeRequest(rawBody: Buffer, parsedBody: unknown): RawBodyRequest<Request> {
  return {
    rawBody,
    body: parsedBody,
    headers: {},
  } as unknown as RawBodyRequest<Request>;
}

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

describe('BranchDeploymentController (BE-60)', () => {
  let controller: BranchDeploymentController;
  let service: {
    syncDeployment: jest.Mock;
    getDeploymentByBranch: jest.Mock;
    getDeploymentsByPr: jest.Mock;
  };
  let config: { githubWebhookSecret: string | undefined };

  beforeEach(() => {
    service = {
      syncDeployment: jest.fn().mockResolvedValue(makeDeployment()),
      getDeploymentByBranch: jest.fn().mockResolvedValue(makeDeployment()),
      getDeploymentsByPr: jest.fn().mockResolvedValue([makeDeployment()]),
    };
    config = { githubWebhookSecret: SECRET };

    controller = new BranchDeploymentController(
      service as unknown as BranchDeploymentService,
      config as unknown as AppConfigService,
    );
  });

  describe('webhook (POST /deployments/webhook)', () => {
    const normalizedPayload = {
      branchName: 'feat/be-branch-metadata-sync',
      prNumber: 544,
      commitSha: COMMIT_SHA,
      previewUrl: 'https://preview-544.quickex.to',
      status: 'deployed',
      environment: 'preview',
      deliveredAt: '2026-08-25T10:00:00.000Z',
    };

    it('ingests a normalized payload with a valid signature', async () => {
      const { rawBody, signature } = sign(normalizedPayload);
      const req = makeRequest(rawBody, normalizedPayload);

      const result = await controller.webhook(req, signature);

      expect(service.syncDeployment).toHaveBeenCalledWith(
        expect.objectContaining({
          branchName: 'feat/be-branch-metadata-sync',
          prNumber: 544,
          commitSha: COMMIT_SHA,
        }),
        'github-webhook',
      );
      expect(result).toMatchObject({ branchName: 'feat/be-branch-metadata-sync', status: 'deployed' });
    });

    it('rejects requests when the webhook secret is not configured', async () => {
      config.githubWebhookSecret = undefined;
      const { rawBody, signature } = sign(normalizedPayload);

      await expect(controller.webhook(makeRequest(rawBody, normalizedPayload), signature)).rejects.toBeInstanceOf(
        ServiceUnavailableException,
      );
    });

    it('rejects requests with an invalid signature', async () => {
      const { rawBody } = sign(normalizedPayload);
      const bogusSignature = `sha256=${'0'.repeat(64)}`;

      await expect(
        controller.webhook(makeRequest(rawBody, normalizedPayload), bogusSignature),
      ).rejects.toBeInstanceOf(UnauthorizedException);
    });

    it('rejects requests with a missing signature', async () => {
      const { rawBody } = sign(normalizedPayload);

      await expect(
        controller.webhook(makeRequest(rawBody, normalizedPayload), undefined),
      ).rejects.toBeInstanceOf(UnauthorizedException);
    });

    it('accepts a native GitHub deployment_status event', async () => {
      const githubEvent = {
        deployment: {
          id: 42,
          sha: COMMIT_SHA,
          ref: 'feat/be-branch-metadata-sync',
          environment: 'preview',
          created_at: '2026-08-25T10:00:00Z',
        },
        deployment_status: {
          id: 99,
          state: 'success',
          environment: 'preview',
          environment_url: 'https://preview-544.quickex.to',
          created_at: '2026-08-25T10:05:00Z',
        },
        pull_request: { number: 544 },
        repository: { full_name: 'Pulsefy/QiuckEx' },
      };
      const { rawBody, signature } = sign(githubEvent);

      await controller.webhook(makeRequest(rawBody, githubEvent), signature);

      expect(service.syncDeployment).toHaveBeenCalledWith(
        expect.objectContaining({
          branchName: 'feat/be-branch-metadata-sync',
          prNumber: 544,
          commitSha: COMMIT_SHA,
          previewUrl: 'https://preview-544.quickex.to',
          status: 'deployed',
        }),
        'github-webhook',
      );
    });

    it('rejects a payload that is neither normalized nor a valid GitHub event', async () => {
      const bogus = { hello: 'world' };
      const { rawBody, signature } = sign(bogus);

      await expect(
        controller.webhook(makeRequest(rawBody, bogus), signature),
      ).rejects.toBeInstanceOf(BadRequestException);
    });
  });

  describe('sync (POST /admin/deployments/sync)', () => {
    it('forwards the admin payload and uses the API key as the audit actor', async () => {
      const dto = new SyncBranchDeploymentDto();
      dto.branchName = 'feat/be-branch-metadata-sync';
      dto.commitSha = COMMIT_SHA;
      dto.previewUrl = 'https://preview-544.quickex.to';
      dto.status = 'deployed';

      const req = { apiKey: { id: 'key-abc' } } as unknown as Request;

      await controller.sync(dto, req);

      expect(service.syncDeployment).toHaveBeenCalledWith(
        expect.objectContaining({ branchName: 'feat/be-branch-metadata-sync' }),
        'key-abc',
      );
    });
  });

  describe('getByBranch (GET /admin/deployments/branch/:branchName)', () => {
    it('returns the latest deployment for a branch', async () => {
      const result = await controller.getByBranch('feat/be-branch-metadata-sync', undefined);

      expect(service.getDeploymentByBranch).toHaveBeenCalledWith(
        'feat/be-branch-metadata-sync',
        undefined,
      );
      expect(result.commitSha).toBe(COMMIT_SHA);
    });

    it('parses an optional ?pr= query parameter', async () => {
      await controller.getByBranch('feat/be-branch-metadata-sync', '544');
      expect(service.getDeploymentByBranch).toHaveBeenCalledWith(
        'feat/be-branch-metadata-sync',
        544,
      );
    });
  });

  describe('getByPr (GET /admin/deployments/pr/:prNumber)', () => {
    it('returns deployment history for a PR', async () => {
      const result = await controller.getByPr(544, undefined);

      expect(service.getDeploymentsByPr).toHaveBeenCalledWith(544, 20);
      expect(result).toHaveLength(1);
      expect(result[0].prNumber).toBe(544);
    });
  });
});
