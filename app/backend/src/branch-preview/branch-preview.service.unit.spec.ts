import { ForbiddenException } from '@nestjs/common';
import { Test, TestingModule } from '@nestjs/testing';
import { BranchPreviewService } from './branch-preview.service';
import { BranchPreviewCache } from './branch-preview.cache';
import { BranchPreviewRepository } from './branch-preview.repository';
import { AuditService } from '../audit/audit.service';
import { BranchPreviewAutoExpiryService } from './branch-preview-auto-expiry.service';

describe('BranchPreviewService', () => {
  let service: BranchPreviewService;
  let cache: jest.Mocked<BranchPreviewCache>;
  let repository: jest.Mocked<BranchPreviewRepository>;
  let auditService: jest.Mocked<AuditService>;

  beforeEach(async () => {
    const mockCache = {
      get: jest.fn(),
      set: jest.fn(),
      delete: jest.fn(),
      clear: jest.fn(),
    };

    const mockRepository = {
      findById: jest.fn(),
      findByBranchName: jest.fn(),
      create: jest.fn(),
      update: jest.fn(),
      delete: jest.fn(),
      findAll: jest.fn(),
      findExpired: jest.fn(),
      touchLastActivity: jest.fn(),
    };

    const mockAutoExpiryService = {
      runAutoExpirySweep: jest.fn(),
    };

    const mockAuditService = {
      log: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        BranchPreviewService,
        { provide: BranchPreviewCache, useValue: mockCache },
        { provide: BranchPreviewRepository, useValue: mockRepository },
        { provide: AuditService, useValue: mockAuditService },
        {
          provide: BranchPreviewAutoExpiryService,
          useValue: mockAutoExpiryService,
        },
      ],
    }).compile();

    service = module.get<BranchPreviewService>(BranchPreviewService);
    cache = module.get(BranchPreviewCache) as jest.Mocked<BranchPreviewCache>;
    repository = module.get(BranchPreviewRepository) as jest.Mocked<BranchPreviewRepository>;
    auditService = module.get(AuditService) as jest.Mocked<AuditService>;
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  it('returns fallback for unknown branch', async () => {
    const branchName = 'unknown-branch-123';
    cache.get.mockReturnValue(undefined);
    repository.findByBranchName.mockResolvedValue(null);

    const result = await service.getPreviewForBranch(branchName);

    expect(result.isFallback).toBe(true);
    expect(result.branchName).toBe('fallback');
  });

  it('returns cached preview when available and valid', async () => {
    const branchName = 'feature/test-branch';
    const mockPreview = {
      id: 'test-id',
      branchName,
      apiUrl: 'https://api.test.com',
      frontendUrl: 'https://app.test.com',
      network: 'testnet' as const,
      contractRegistryVersion: 'v1.0.0',
      isActive: true,
      isShared: false,
      expiryExempt: false,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    cache.get.mockReturnValue(mockPreview);

    const result = await service.getPreviewForBranch(branchName);

    expect(result.isFallback).toBe(false);
    expect(result.apiUrl).toBe('https://api.test.com');
    expect(repository.findByBranchName).not.toHaveBeenCalled();
  });

  it('fetches from database when cache miss', async () => {
    const branchName = 'feature/database-test';
    const mockPreview = {
      id: 'test-id-2',
      branchName,
      apiUrl: 'https://api.db-test.com',
      frontendUrl: 'https://app.db-test.com',
      network: 'testnet' as const,
      contractRegistryVersion: 'v1.1.0',
      isActive: true,
      isShared: false,
      expiryExempt: false,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    cache.get.mockReturnValue(undefined);
    repository.findByBranchName.mockResolvedValue(mockPreview);

    const result = await service.getPreviewForBranch(branchName);

    expect(result.apiUrl).toBe('https://api.db-test.com');
    expect(cache.set).toHaveBeenCalledWith(branchName.toLowerCase(), mockPreview);
  });

  it('returns fallback for stale/expired preview', async () => {
    const branchName = 'feature/expired-branch';
    const expiredPreview = {
      id: 'expired-id',
      branchName,
      apiUrl: 'https://api.expired.com',
      frontendUrl: 'https://app.expired.com',
      network: 'testnet' as const,
      contractRegistryVersion: 'v0.9.0',
      isActive: true,
      isShared: false,
      expiryExempt: false,
      createdAt: new Date(Date.now() - 86400000),
      updatedAt: new Date(Date.now() - 86400000),
      expiresAt: new Date(Date.now() - 3600000), // Expired 1 hour ago
    };

    cache.get.mockReturnValue(expiredPreview);
    repository.findByBranchName.mockResolvedValue(expiredPreview);

    const result = await service.getPreviewForBranch(branchName);

    expect(result.isFallback).toBe(true);
  });

  it('rejects create operations when a reviewer targets a different branch', async () => {
    await expect(
      service.createPreview(
        {
          branchName: 'feature/other-branch',
          apiUrl: 'https://api.example.com',
          frontendUrl: 'https://app.example.com',
          network: 'testnet',
          contractRegistryVersion: 'v1',
        },
        'actor-1',
        'req-1',
        {
          actorId: 'actor-1',
          role: 'reviewer',
          branchName: 'feature/owned-branch',
        },
      ),
    ).rejects.toBeInstanceOf(ForbiddenException);

    expect(repository.create).not.toHaveBeenCalled();
  });

  it('logs destructive actions for admin cleanup operations', async () => {
    await service.clearAllCache('admin-1', 'req-2', {
      actorId: 'admin-1',
      role: 'admin',
    });

    expect(auditService.log).toHaveBeenCalledWith(
      'admin-1',
      'branch_preview.cache_cleared',
      'all',
      expect.objectContaining({ destructive: true }),
      'req-2',
    );
  });
});
