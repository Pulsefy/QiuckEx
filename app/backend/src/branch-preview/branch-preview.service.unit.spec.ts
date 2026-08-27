import { Test, TestingModule } from "@nestjs/testing";
import { BranchPreviewService } from "./branch-preview.service";
import { BranchPreviewCache } from "./branch-preview.cache";
import { BranchPreviewRepository } from "./branch-preview.repository";
import { AuditService } from "../audit/audit.service";
import { BranchPreviewAutoExpiryService } from "./branch-preview-auto-expiry.service";

describe("BranchPreviewService", () => {
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
      findById: jest.fn(),
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
    repository = module.get(
      BranchPreviewRepository,
    ) as jest.Mocked<BranchPreviewRepository>;
  });

  it("should be defined", () => {
    expect(service).toBeDefined();
  });

  it("returns fallback for unknown branch", async () => {
    const branchName = "unknown-branch-123";
    cache.get.mockReturnValue(undefined);
    repository.findByBranchName.mockResolvedValue(null);

    const result = await service.getPreviewForBranch(branchName);

    expect(result.isFallback).toBe(true);
    expect(result.branchName).toBe("fallback");
  });

  it("returns cached preview when available and valid", async () => {
    const branchName = "feature/test-branch";
    const mockPreview = {
      id: "test-id",
      branchName,
      apiUrl: "https://api.test.com",
      frontendUrl: "https://app.test.com",
      network: "testnet" as const,
      contractRegistryVersion: "v1.0.0",
      isActive: true,
      isShared: false,
      expiryExempt: false,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    cache.get.mockReturnValue(mockPreview);

    const result = await service.getPreviewForBranch(branchName);

    expect(result.isFallback).toBe(false);
    expect(result.apiUrl).toBe("https://api.test.com");
    expect(repository.findByBranchName).not.toHaveBeenCalled();
  });

  it("fetches from database when cache miss", async () => {
    const branchName = "feature/database-test";
    const mockPreview = {
      id: "test-id-2",
      branchName,
      apiUrl: "https://api.db-test.com",
      frontendUrl: "https://app.db-test.com",
      network: "testnet" as const,
      contractRegistryVersion: "v1.1.0",
      isActive: true,
      isShared: false,
      expiryExempt: false,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    cache.get.mockReturnValue(undefined);
    repository.findByBranchName.mockResolvedValue(mockPreview);

    const result = await service.getPreviewForBranch(branchName);

    expect(result.apiUrl).toBe("https://api.db-test.com");
    expect(cache.set).toHaveBeenCalledWith(branchName, mockPreview);
  });

  it("returns fallback for stale/expired preview", async () => {
    const branchName = "feature/expired-branch";
    const expiredPreview = {
      id: "expired-id",
      branchName,
      apiUrl: "https://api.expired.com",
      frontendUrl: "https://app.expired.com",
      network: "testnet" as const,
      contractRegistryVersion: "v0.9.0",
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

  describe("permissions and authorization", () => {
    it("allows admin to update preview", async () => {
      const mockPreview = { id: "test-id", branchName: "b", ownerId: "user-1", apiUrl: "foo", frontendUrl: "foo", network: "testnet" as const, contractRegistryVersion: "latest", isActive: true, isShared: false, expiryExempt: false, createdAt: new Date(), updatedAt: new Date() };
      repository.findById.mockResolvedValue(mockPreview);
      repository.update.mockResolvedValue({ ...mockPreview, apiUrl: "bar" });
      
      const result = await service.updatePreview("test-id", { apiUrl: "bar" }, "admin-user", ["admin"]);
      expect(result.apiUrl).toBe("bar");
    });

    it("allows reviewer to delete preview", async () => {
      const mockPreview = { id: "test-id", branchName: "b", ownerId: "user-1", apiUrl: "foo", frontendUrl: "foo", network: "testnet" as const, contractRegistryVersion: "latest", isActive: true, isShared: false, expiryExempt: false, createdAt: new Date(), updatedAt: new Date() };
      repository.findById.mockResolvedValue(mockPreview);
      repository.delete.mockResolvedValue(undefined);
      
      await expect(service.deletePreview("test-id", "reviewer-user", ["branch_preview:reviewer"])).resolves.not.toThrow();
    });

    it("allows owner to update their preview", async () => {
      const mockPreview = { id: "test-id", branchName: "b", ownerId: "user-owner", apiUrl: "foo", frontendUrl: "foo", network: "testnet" as const, contractRegistryVersion: "latest", isActive: true, isShared: false, expiryExempt: false, createdAt: new Date(), updatedAt: new Date() };
      repository.findById.mockResolvedValue(mockPreview);
      repository.update.mockResolvedValue({ ...mockPreview, apiUrl: "bar" });
      
      const result = await service.updatePreview("test-id", { apiUrl: "bar" }, "user-owner", ["some:other:scope"]);
      expect(result.apiUrl).toBe("bar");
    });

    it("throws ForbiddenException when unauthorized user attempts to update", async () => {
      const mockPreview = { id: "test-id", branchName: "b", ownerId: "user-owner", apiUrl: "foo", frontendUrl: "foo", network: "testnet" as const, contractRegistryVersion: "latest", isActive: true, isShared: false, expiryExempt: false, createdAt: new Date(), updatedAt: new Date() };
      repository.findById.mockResolvedValue(mockPreview);
      
      await expect(service.updatePreview("test-id", { apiUrl: "bar" }, "unauthorized-user", ["some:scope"])).rejects.toThrow("You do not have permission to modify this preview environment");
    });

    it("throws ForbiddenException when unauthorized user attempts to delete", async () => {
      const mockPreview = { id: "test-id", branchName: "b", ownerId: "user-owner", apiUrl: "foo", frontendUrl: "foo", network: "testnet" as const, contractRegistryVersion: "latest", isActive: true, isShared: false, expiryExempt: false, createdAt: new Date(), updatedAt: new Date() };
      repository.findById.mockResolvedValue(mockPreview);
      
      await expect(service.deletePreview("test-id", "unauthorized-user", ["some:scope"])).rejects.toThrow("You do not have permission to delete this preview environment");
    });

    it("throws ForbiddenException when unauthorized user attempts to invalidate cache", async () => {
      const mockPreview = { id: "test-id", branchName: "test-branch", ownerId: "user-owner", apiUrl: "foo", frontendUrl: "foo", network: "testnet" as const, contractRegistryVersion: "latest", isActive: true, isShared: false, expiryExempt: false, createdAt: new Date(), updatedAt: new Date() };
      repository.findByBranchName.mockResolvedValue(mockPreview);
      
      await expect(service.invalidateCache("test-branch", "unauthorized-user", ["some:scope"])).rejects.toThrow("You do not have permission to invalidate cache for this preview environment");
    });
  });
});
