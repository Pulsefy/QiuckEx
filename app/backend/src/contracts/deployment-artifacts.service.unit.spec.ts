import { BadRequestException, NotFoundException } from '@nestjs/common';
import { createHash } from 'crypto';

import { SupabaseService } from '../supabase/supabase.service';
import { AppConfigService } from '../config';
import { AuditService } from '../audit/audit.service';
import { DeploymentArtifactsService } from './deployment-artifacts.service';

describe('DeploymentArtifactsService', () => {
  let service: DeploymentArtifactsService;
  let mockAuditService: jest.Mocked<Partial<AuditService>>;

  beforeEach(() => {
    // Force fallback (in-memory) storage: Supabase client throws.
    const mockSupabaseService: Partial<SupabaseService> = {
      getClient: jest.fn(() => {
        throw new Error('supabase unavailable');
      }) as never,
    };

    const mockAppConfigService: Partial<AppConfigService> = {
      network: 'testnet',
    };

    mockAuditService = {
      log: jest.fn().mockResolvedValue(undefined),
    };

    service = new DeploymentArtifactsService(
      mockSupabaseService as SupabaseService,
      mockAppConfigService as AppConfigService,
      mockAuditService as unknown as AuditService,
    );
  });

  it('uploads an artifact, computes its checksum, and audits the upload', async () => {
    const content = Buffer.from('{"contract":"quickex"}').toString('base64');

    const result = await service.upload(
      {
        deploymentId: 'deploy-1',
        artifactType: 'deploy_manifest',
        contentBase64: content,
      },
      'api-key-1',
    );

    expect(result.deploymentId).toBe('deploy-1');
    expect(result.artifactType).toBe('deploy_manifest');
    expect(result.checksumSha256).toBe(
      createHash('sha256').update(Buffer.from(content, 'base64')).digest('hex'),
    );
    expect(mockAuditService.log).toHaveBeenCalledWith(
      'api-key-1',
      'deployment_artifact.uploaded',
      result.id,
      expect.objectContaining({ deploymentId: 'deploy-1' }),
    );
  });

  it('rejects non-base64 / empty content', async () => {
    await expect(
      service.upload(
        { deploymentId: 'deploy-1', artifactType: 'deploy_manifest', contentBase64: '' },
        'api-key-1',
      ),
    ).rejects.toBeInstanceOf(BadRequestException);
  });

  it('lists artifacts filtered by deploymentId and artifactType', async () => {
    const content = Buffer.from('report').toString('base64');
    await service.upload(
      { deploymentId: 'deploy-1', artifactType: 'smoke_report', contentBase64: content },
      'api-key-1',
    );
    await service.upload(
      { deploymentId: 'deploy-2', artifactType: 'deploy_manifest', contentBase64: content },
      'api-key-1',
    );

    const filtered = await service.list({ deploymentId: 'deploy-1' });
    expect(filtered).toHaveLength(1);
    expect(filtered[0].deploymentId).toBe('deploy-1');

    const byType = await service.list({ artifactType: 'deploy_manifest' });
    expect(byType).toHaveLength(1);
    expect(byType[0].artifactType).toBe('deploy_manifest');
  });

  it('downloads an artifact and reports checksum validity', async () => {
    const content = Buffer.from('report-body').toString('base64');
    const uploaded = await service.upload(
      { deploymentId: 'deploy-1', artifactType: 'smoke_report', contentBase64: content },
      'api-key-1',
    );

    const downloaded = await service.download(uploaded.id);
    expect(downloaded.contentBase64).toBe(content);
    expect(downloaded.checksumValid).toBe(true);
  });

  it('throws NotFoundException when downloading a nonexistent artifact', async () => {
    await expect(service.download('does-not-exist')).rejects.toBeInstanceOf(NotFoundException);
  });

  it('detects checksum corruption on download', async () => {
    const content = Buffer.from('original').toString('base64');
    const uploaded = await service.upload(
      { deploymentId: 'deploy-1', artifactType: 'registry_snapshot', contentBase64: content },
      'api-key-1',
    );

    // Simulate corruption by mutating the fallback store directly.
    const store = (service as unknown as { fallbackStore: Map<string, { content: string }> })
      .fallbackStore;
    store.get(uploaded.id)!.content = Buffer.from('tampered').toString('base64');

    const downloaded = await service.download(uploaded.id);
    expect(downloaded.checksumValid).toBe(false);
  });

  it('cleanupExpired removes artifacts past their retention window', async () => {
    const content = Buffer.from('expiring').toString('base64');
    const uploaded = await service.upload(
      { deploymentId: 'deploy-1', artifactType: 'deploy_manifest', contentBase64: content },
      'api-key-1',
    );

    const store = (service as unknown as { fallbackStore: Map<string, { retentionUntil: string }> })
      .fallbackStore;
    store.get(uploaded.id)!.retentionUntil = new Date(Date.now() - 1000).toISOString();

    const deletedCount = await service.cleanupExpired();
    expect(deletedCount).toBe(1);
    await expect(service.download(uploaded.id)).rejects.toBeInstanceOf(NotFoundException);
  });
});
