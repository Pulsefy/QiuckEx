import { Test, TestingModule } from "@nestjs/testing";
import { NotFoundException } from "@nestjs/common";
import * as bcrypt from "bcrypt";
import { ApiKeysService } from "./api-keys.service";
import { ApiKeysRepository } from "./api-keys.repository";
import { ApiKeyRecord } from "./api-keys.types";
import { AppConfigService } from "../config/app-config.service";
import { AuditService } from "../audit/audit.service";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const makeRecord = (overrides: Partial<ApiKeyRecord> = {}): ApiKeyRecord => ({
  id: "test-uuid-1234",
  name: "Test Key",
  key_hash: "$2b$10$hashedvalue",
  key_hash_old: null,
  key_prefix: "qx_live_abc",
  scopes: ["links:read"],
  owner_id: null,
  organization_id: null,
  is_active: true,
  request_count: 0,
  monthly_quota: 10000,
  last_used_at: null,
  rotated_at: null,
  last_reset_at: new Date().toISOString(),
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
  ...overrides,
});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("ApiKeysService", () => {
  let service: ApiKeysService;
  let repo: jest.Mocked<ApiKeysRepository>;
  let auditService: jest.Mocked<AuditService>;
  let configService: { apiKeyRotationOverlapHours: number };

  beforeEach(async () => {
    const mockRepo: jest.Mocked<Partial<ApiKeysRepository>> = {
      insert: jest.fn(),
      findAll: jest.fn(),
      findAllPaginated: jest.fn(),
      findById: jest.fn(),
      findByPrefix: jest.fn(),
      revoke: jest.fn(),
      updateKey: jest.fn(),
      emergencyUpdateKey: jest.fn(),
      incrementUsage: jest.fn(),
      getUsageSummary: jest.fn(),
    };

    const mockAuditService: jest.Mocked<Partial<AuditService>> = {
      log: jest.fn().mockResolvedValue(undefined),
    };

    configService = {
      apiKeyRotationOverlapHours: 24,
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ApiKeysService,
        { provide: ApiKeysRepository, useValue: mockRepo },
        { provide: AuditService, useValue: mockAuditService },
        { provide: AppConfigService, useValue: configService },
      ],
    }).compile();

    service = module.get<ApiKeysService>(ApiKeysService);
    repo = module.get(ApiKeysRepository);
    auditService = module.get(AuditService);
  });

  it("should be defined", () => {
    expect(service).toBeDefined();
  });

  // -------------------------------------------------------------------------
  // create
  // -------------------------------------------------------------------------

  describe("create", () => {
    it("returns a public record with the raw key", async () => {
      const record = makeRecord();
      repo.insert.mockResolvedValue(record);

      const result = await service.create({
        name: "Test Key",
        scopes: ["links:read"],
      });

      expect(result.key).toMatch(/^qx_live_[a-f0-9]+$/);
      expect(result.id).toBe(record.id);
      expect(result.name).toBe(record.name);
      expect(result.scopes).toEqual(["links:read"]);
      // raw key must NOT be stored in key_hash directly
      expect(result.key).not.toBe(result.key_prefix);
    });

    it("stores a bcrypt hash, not the raw key", async () => {
      const record = makeRecord();
      repo.insert.mockResolvedValue(record);

      await service.create({ name: "Test Key", scopes: ["links:read"] });

      const insertedHash = repo.insert.mock.calls[0][0].key_hash;
      expect(insertedHash).toMatch(/^\$2b\$/); // bcrypt prefix
    });

    it("generates a prefix matching the stored key_prefix format", async () => {
      const record = makeRecord();
      repo.insert.mockResolvedValue(record);

      await service.create({ name: "Test Key", scopes: ["links:read"] });

      const insertedPrefix = repo.insert.mock.calls[0][0].key_prefix;
      expect(insertedPrefix).toMatch(/^qx_live_/);
    });

    it("logs audit entry on create with non-sensitive metadata", async () => {
      const record = makeRecord({
        id: "key-123",
        name: "Test Key",
        scopes: ["links:read", "links:write"],
        owner_id: "owner-1",
        organization_id: "org-1",
      });
      repo.insert.mockResolvedValue(record);

      const result = await service.create(
        {
          name: "Test Key",
          scopes: ["links:read", "links:write"],
          owner_id: "owner-1",
          organization_id: "org-1",
        },
        "admin-user-1",
      );

      expect(auditService.log).toHaveBeenCalledTimes(1);
      expect(auditService.log).toHaveBeenCalledWith(
        "admin-user-1",
        "api_key.created",
        "key-123",
        {
          name: "Test Key",
          scopes: ["links:read", "links:write"],
          owner_id: "owner-1",
          organization_id: "org-1",
        },
      );

      // Verify raw key or hash is NEVER passed in metadata
      const metadata = (auditService.log as jest.Mock).mock.calls[0][3];
      expect(metadata).not.toHaveProperty("key");
      expect(metadata).not.toHaveProperty("key_hash");
      expect(JSON.stringify(metadata)).not.toContain(result.key);
      expect(JSON.stringify(metadata)).not.toContain(record.key_hash);
    });
  });

  // -------------------------------------------------------------------------
  // list
  // -------------------------------------------------------------------------

  describe("list", () => {
    it("returns mapped public records without key_hash", async () => {
      const record = makeRecord();
      repo.findAll.mockResolvedValue([record]);

      const result = await service.list();

      expect(result).toHaveLength(1);
      expect(result[0]).not.toHaveProperty("key_hash");
      expect(result[0]).not.toHaveProperty("updated_at");
      expect(result[0].id).toBe(record.id);
    });

    it("forwards owner_id filter to repository", async () => {
      repo.findAll.mockResolvedValue([]);
      await service.list("wallet-abc");
      expect(repo.findAll).toHaveBeenCalledWith("wallet-abc", undefined);
    });
  });

  // -------------------------------------------------------------------------
  // revoke
  // -------------------------------------------------------------------------

  describe("revoke", () => {
    it("calls repo.revoke and logs audit entry when key exists", async () => {
      const record = makeRecord({ id: "test-uuid-1234", name: "My Key", scopes: ["links:read"] });
      repo.findById.mockResolvedValue(record);
      repo.revoke.mockResolvedValue(undefined);

      await service.revoke("test-uuid-1234", "admin-actor");

      expect(repo.revoke).toHaveBeenCalledWith("test-uuid-1234");
      expect(auditService.log).toHaveBeenCalledWith(
        "admin-actor",
        "api_key.revoked",
        "test-uuid-1234",
        {
          name: "My Key",
          scopes: ["links:read"],
          owner_id: null,
          organization_id: null,
        },
      );

      const metadata = (auditService.log as jest.Mock).mock.calls[0][3];
      expect(metadata).not.toHaveProperty("key_hash");
    });

    it("throws NotFoundException when key does not exist", async () => {
      repo.findById.mockResolvedValue(null);

      await expect(service.revoke("missing-id")).rejects.toThrow(
        NotFoundException,
      );
      expect(repo.revoke).not.toHaveBeenCalled();
      expect(auditService.log).not.toHaveBeenCalled();
    });
  });

  // -------------------------------------------------------------------------
  // rotate
  // -------------------------------------------------------------------------

  describe("rotate", () => {
    it("returns a new raw key and updated record, and writes audit log", async () => {
      const original = makeRecord({ key_prefix: "qx_live_old" });
      const updated = makeRecord({
        key_prefix: "qx_live_new",
        key_hash: "$2b$10$newhashvalue",
      });
      repo.findById.mockResolvedValue(original);
      repo.updateKey.mockResolvedValue(updated);

      const result = await service.rotate("test-uuid-1234", "admin-rotator");

      expect(result.key).toMatch(/^qx_live_[a-f0-9]+$/);
      expect(repo.updateKey).toHaveBeenCalledWith(
        "test-uuid-1234",
        expect.objectContaining({ key_hash: expect.stringMatching(/^\$2b\$/) }),
      );

      expect(auditService.log).toHaveBeenCalledWith(
        "admin-rotator",
        "api_key.rotated",
        "test-uuid-1234",
        {
          name: updated.name,
          scopes: updated.scopes,
          owner_id: updated.owner_id,
          organization_id: updated.organization_id,
        },
      );

      const metadata = (auditService.log as jest.Mock).mock.calls[0][3];
      expect(metadata).not.toHaveProperty("key_hash");
      expect(JSON.stringify(metadata)).not.toContain(result.key);
    });

    it("throws NotFoundException when key does not exist", async () => {
      repo.findById.mockResolvedValue(null);

      await expect(service.rotate("missing-id")).rejects.toThrow(
        NotFoundException,
      );
      expect(auditService.log).not.toHaveBeenCalled();
    });
  });

  // -------------------------------------------------------------------------
  // emergencyRotate
  // -------------------------------------------------------------------------

  describe("emergencyRotate", () => {
    it("immediately rotates key and logs emergency_rotated audit entry", async () => {
      const original = makeRecord({ id: "emergency-id" });
      const updated = makeRecord({ id: "emergency-id", key_prefix: "qx_live_newp" });
      repo.findById.mockResolvedValue(original);
      repo.emergencyUpdateKey.mockResolvedValue(updated);

      const result = await service.emergencyRotate("emergency-id", "security-admin");

      expect(result.key).toMatch(/^qx_live_[a-f0-9]+$/);
      expect(repo.emergencyUpdateKey).toHaveBeenCalledWith(
        "emergency-id",
        expect.objectContaining({ key_hash: expect.stringMatching(/^\$2b\$/) }),
      );
      expect(auditService.log).toHaveBeenCalledWith(
        "security-admin",
        "api_key.emergency_rotated",
        "emergency-id",
        {
          name: updated.name,
          scopes: updated.scopes,
          owner_id: updated.owner_id,
          organization_id: updated.organization_id,
        },
      );
    });
  });

  // -------------------------------------------------------------------------
  // validateKey & Configurable Overlap Window
  // -------------------------------------------------------------------------

  describe("validateKey", () => {
    it("returns null when no candidates match the prefix", async () => {
      repo.findByPrefix.mockResolvedValue([]);

      const result = await service.validateKey("qx_live_abc123fakekeyvalue");

      expect(result).toBeNull();
    });

    it("returns null when prefix matches but bcrypt compare fails", async () => {
      const record = makeRecord({
        key_hash:
          "$2b$10$invalidhashvalue000000000000000000000000000000000000000",
      });
      repo.findByPrefix.mockResolvedValue([record]);
      repo.incrementUsage.mockResolvedValue(undefined);

      const result = await service.validateKey(
        "qx_live_wrongkey12345678901234567890123456789012345678",
      );

      expect(result).toBeNull();
    });

    it("returns record when key matches key_hash_old within default 24h overlap window", async () => {
      const oldHash = await bcrypt.hash(
        "qx_live_oldkey12345678901234567890",
        10,
      );
      const record = makeRecord({
        key_hash: "$2b$10$newhashvalue...",
        key_hash_old: oldHash,
        rotated_at: new Date(Date.now() - 23 * 60 * 60 * 1000).toISOString(), // 23h ago
      });
      repo.findByPrefix.mockResolvedValue([record]);
      repo.incrementUsage.mockResolvedValue(undefined);

      const result = await service.validateKey(
        "qx_live_oldkey12345678901234567890",
      );

      expect(result).not.toBeNull();
      expect(result?.record.id).toBe(record.id);
    });

    it("returns null when key matches key_hash_old but after default 24h overlap window", async () => {
      const oldHash = await bcrypt.hash(
        "qx_live_oldkey12345678901234567890",
        10,
      );
      const record = makeRecord({
        key_hash: "$2b$10$newhashvalue...",
        key_hash_old: oldHash,
        rotated_at: new Date(Date.now() - 25 * 60 * 60 * 1000).toISOString(), // 25h ago
      });
      repo.findByPrefix.mockResolvedValue([record]);

      const result = await service.validateKey(
        "qx_live_oldkey12345678901234567890",
      );

      expect(result).toBeNull();
    });

    it("respects custom configured overlap window (e.g. 2 hours)", async () => {
      configService.apiKeyRotationOverlapHours = 2;

      const oldHash = await bcrypt.hash(
        "qx_live_customoverlap1234567890123",
        10,
      );

      // Case 1: rotated 1 hour ago (within 2h window) -> match
      const recordWithin = makeRecord({
        id: "key-within-2h",
        key_hash: "$2b$10$newhashvalue...",
        key_hash_old: oldHash,
        rotated_at: new Date(Date.now() - 1 * 60 * 60 * 1000).toISOString(),
      });
      repo.findByPrefix.mockResolvedValue([recordWithin]);
      repo.incrementUsage.mockResolvedValue(undefined);

      const resultWithin = await service.validateKey(
        "qx_live_customoverlap1234567890123",
      );
      expect(resultWithin).not.toBeNull();
      expect(resultWithin?.record.id).toBe("key-within-2h");

      // Case 2: rotated 3 hours ago (past 2h window) -> rejected
      const recordPast = makeRecord({
        id: "key-past-2h",
        key_hash: "$2b$10$newhashvalue...",
        key_hash_old: oldHash,
        rotated_at: new Date(Date.now() - 3 * 60 * 60 * 1000).toISOString(),
      });
      repo.findByPrefix.mockResolvedValue([recordPast]);

      const resultPast = await service.validateKey(
        "qx_live_customoverlap1234567890123",
      );
      expect(resultPast).toBeNull();
    });
  });

  // -------------------------------------------------------------------------
  // isOverQuota
  // -------------------------------------------------------------------------

  describe("isOverQuota", () => {
    it("returns false when usage is below quota", () => {
      const record = makeRecord({ request_count: 5000, monthly_quota: 10000 });
      expect(service.isOverQuota(record)).toBe(false);
    });

    it("returns true when usage equals quota", () => {
      const record = makeRecord({ request_count: 10000, monthly_quota: 10000 });
      expect(service.isOverQuota(record)).toBe(true);
    });

    it("returns true when usage exceeds quota", () => {
      const record = makeRecord({ request_count: 10001, monthly_quota: 10000 });
      expect(service.isOverQuota(record)).toBe(true);
    });

    it("returns false if current month is later than last_reset_at", () => {
      const lastMonth = new Date();
      lastMonth.setUTCDate(1);
      lastMonth.setUTCMonth(lastMonth.getUTCMonth() - 1);

      const record = makeRecord({
        request_count: 15000,
        monthly_quota: 10000,
        last_reset_at: lastMonth.toISOString(),
      });

      expect(service.isOverQuota(record)).toBe(false);
    });
  });
});
