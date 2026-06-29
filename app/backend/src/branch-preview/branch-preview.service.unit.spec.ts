import { Test, TestingModule } from '@nestjs/testing';
import { BranchPreviewService } from './branch-preview.service';
import { BranchPreviewCache } from './branch-preview.cache';
import { BranchPreviewRepository } from './branch-preview.repository';
import { AuditService } from '../audit/audit.service';

describe('BranchPreviewService', () => {
  let service: BranchPreviewService;
  let cache: jest.Mocked<BranchPreviewCache>;
  let repository: jest.Mocked<BranchPreviewRepository>;

  beforeEach(async () => {
    const mockCache = {
      get: jest.fn(),
      set: jest.fn(),
      delete: jest.fn(),
      clear: jest.fn(),
    };

    const mockRepository = {
      findByBranchName: jest.fn(),
      create: jest.fn(),
      update: jest.fn(),
      delete: jest.fn(),
      findAll: jest.fn(),
      findExpired: jest.fn(),
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
      ],
    }).compile();

    service = module.get<BranchPreviewService>(BranchPreviewService);
    cache = module.get(BranchPreviewCache) as jest.Mocked<BranchPreviewCache>;
    repository = module.get(BranchPreviewRepository) as jest.Mocked<BranchPreviewRepository>;
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
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    
    cache.get.mockReturnValue(mockPreview);

    const result = await service.getPreviewForBranch(branchName);
    
    expect(result.isFallback).toBeUndefined();
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
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    
    cache.get.mockReturnValue(undefined);
    repository.findByBranchName.mockResolvedValue(mockPreview);

    const result = await service.getPreviewForBranch(branchName);
    
    expect(result.apiUrl).toBe('https://api.db-test.com');
    expect(cache.set).toHaveBeenCalledWith(branchName, mockPreview, undefined);
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
      createdAt: new Date(Date.now() - 86400000),
      updatedAt: new Date(Date.now() - 86400000),
      expiresAt: new Date(Date.now() - 3600000), // Expired 1 hour ago
    };
    
    cache.get.mockReturnValue(expiredPreview);
    repository.findByBranchName.mockResolvedValue(expiredPreview);

    const result = await service.getPreviewForBranch(branchName);
    
    expect(result.isFallback).toBe(true);
  });
});