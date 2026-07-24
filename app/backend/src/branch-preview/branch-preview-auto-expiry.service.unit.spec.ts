import { Test } from '@nestjs/testing';
import { EventEmitter2 } from '@nestjs/event-emitter';

import { BranchPreviewAutoExpiryService } from './branch-preview-auto-expiry.service';
import { BranchPreviewRepository } from './branch-preview.repository';
import { BranchPreviewCache } from './branch-preview.cache';
import { AuditService } from '../audit/audit.service';
import { SupabaseService } from '../supabase/supabase.service';
import {
  BRANCH_PREVIEW_AUTO_EXPIRED_EVENT,
  DEFAULT_PREVIEW_INACTIVITY_THRESHOLD_MS,
  PREVIEW_AUTO_EXPIRY_WORKER_ACTOR,
} from './branch-preview-expiry.config';
import { BranchPreviewEnvironment } from './branch-preview.model';

describe('BranchPreviewAutoExpiryService', () => {
  let service: BranchPreviewAutoExpiryService;
  let repository: jest.Mocked<Pick<BranchPreviewRepository, 'findActiveForAutoExpiryEvaluation' | 'deactivateForAutoExpiry'>>;
  let cache: jest.Mocked<Pick<BranchPreviewCache, 'delete'>>;
  let audit: jest.Mocked<Pick<AuditService, 'log'>>;
  let events: EventEmitter2;
  let insertMock: jest.Mock;

  const now = new Date('2026-07-24T12:00:00.000Z');

  beforeEach(async () => {
    insertMock = jest.fn().mockResolvedValue({ data: [], error: null });
    const supabaseClient = {
      from: jest.fn().mockReturnValue({ insert: insertMock }),
    };

    repository = {
      findActiveForAutoExpiryEvaluation: jest.fn(),
      deactivateForAutoExpiry: jest.fn(),
    };
    cache = { delete: jest.fn() };
    audit = { log: jest.fn().mockResolvedValue(undefined) };
    events = new EventEmitter2();

    const module = await Test.createTestingModule({
      providers: [
        BranchPreviewAutoExpiryService,
        { provide: BranchPreviewRepository, useValue: repository },
        { provide: BranchPreviewCache, useValue: cache },
        { provide: AuditService, useValue: audit },
        { provide: SupabaseService, useValue: { getClient: () => supabaseClient } },
        { provide: EventEmitter2, useValue: events },
      ],
    }).compile();

    service = module.get(BranchPreviewAutoExpiryService);
  });

  function stalePreview(): BranchPreviewEnvironment {
    return {
      id: 'p-1',
      branchName: 'feat/stale',
      apiUrl: 'https://api.example.com',
      frontendUrl: 'https://app.example.com',
      network: 'testnet',
      contractRegistryVersion: 'v1',
      isActive: true,
      isShared: false,
      expiryExempt: false,
      createdAt: new Date(now.getTime() - 60_000),
      updatedAt: now,
      lastActivityAt: new Date(now.getTime() - DEFAULT_PREVIEW_INACTIVITY_THRESHOLD_MS),
    };
  }

  it('deactivates stale previews, audits, and emits cleanup hook', async () => {
    const preview = stalePreview();
    const deactivated = { ...preview, isActive: false, autoExpiryReason: 'inactivity' };

    repository.findActiveForAutoExpiryEvaluation.mockResolvedValue([preview]);
    repository.deactivateForAutoExpiry.mockResolvedValue(deactivated);

    const emitSpy = jest.spyOn(events, 'emit');

    const count = await service.runAutoExpirySweep('run-abc', now);

    expect(count).toBe(1);
    expect(repository.deactivateForAutoExpiry).toHaveBeenCalledWith(
      preview.id,
      'inactivity',
      now,
    );
    expect(cache.delete).toHaveBeenCalledWith(preview.branchName);
    expect(audit.log).toHaveBeenCalledWith(
      PREVIEW_AUTO_EXPIRY_WORKER_ACTOR,
      'branch_preview.auto_expired',
      preview.id,
      expect.objectContaining({ reason: 'inactivity', runId: 'run-abc' }),
    );
    expect(insertMock).toHaveBeenCalled();
    expect(emitSpy).toHaveBeenCalledWith(
      BRANCH_PREVIEW_AUTO_EXPIRED_EVENT,
      expect.objectContaining({ branchName: preview.branchName, reason: 'inactivity' }),
    );
  });

  it('skips shared previews returned from repository without deactivating', async () => {
    const shared = { ...stalePreview(), isShared: true };
    repository.findActiveForAutoExpiryEvaluation.mockResolvedValue([shared]);

    const count = await service.runAutoExpirySweep('run-shared', now);

    expect(count).toBe(0);
    expect(repository.deactivateForAutoExpiry).not.toHaveBeenCalled();
  });
});
