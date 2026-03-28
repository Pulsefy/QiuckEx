import { Test, TestingModule } from '@nestjs/testing';
import { NotFoundException } from '@nestjs/common';
import { ApiKeysService } from './api-keys.service';
import { ApiKeysRepository } from './api-keys.repository';
import { ApiKeyRecord } from './api-keys.types';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const makeRecord = (overrides: Partial<ApiKeyRecord> = {}): ApiKeyRecord => ({
  id: 'test-uuid-1234',
  name: 'Test Key',
  key_hash: '$2b$10$hashedvalue',
  key_prefix: 'qx_live_abc',
  scopes: ['links:read'],
  owner_id: null,
  is_active: true,
  request_count: 0,
  monthly_quota: 10000,
  last_used_at: null,
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
  ...overrides,
});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('ApiKeysService', () => {
  let service: ApiKeysService;
  let repo: jest.Mocked<ApiKeysRepository>;

  beforeEach(async () => {
    const mockRepo: jest.Mocked<Partial<ApiKeysRepository>> = {
      insert: jest.fn(),
      findAll: jest.fn(),
      findById: jest.fn(),
      findByPrefix: jest.fn(),
      revoke: jest.fn(),
      updateKey: jest.fn(),
      incrementUsage: jest.fn(),
      getUsageSummary: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ApiKeysService,
        { provide: ApiKeysRepository, useValue: mockRepo },
      ],
    }).compile();

    service = module.get<ApiKeysService>(ApiKeysService);
    repo = module.get(ApiKeysRepository);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  // -------------------------------------------------------------------------
  // create
  // -------------------------------------------------------------------------

  describe('create', () => {
    it('returns a public record with the raw key', async () => {
      const record = makeRecord();
      repo.insert.mockResolvedValue(record);

      const result = await service.create({
        name: 'Test Key',
        scopes: ['links:read'],
      });

      expect(result.key).toMatch(/^qx_live_[a-f0-9]+$/);
      expect(result.id).toBe(record.id);
      expect(result.name).toBe(record.name);
      expect(result.scopes).toEqual(['links:read']);
      // raw key must NOT be stored in key_hash directly
      expect(result.key).not.toBe(result.key_prefix);
    });

    it('stores a bcrypt hash, not the raw key', async () => {
      const record = makeRecord();
      repo.insert.mockResolvedValue(record);

      await service.create({ name: 'Test Key', scopes: ['links:read'] });

      const insertedHash = repo.insert.mock.calls[0][0].key_hash;
      expect(insertedHash).toMatch(/^\$2b\$/); // bcrypt prefix
    });

    it('generates a prefix matching the stored key_prefix format', async () => {
      const record = makeRecord();
      repo.insert.mockResolvedValue(record);

      await service.create({ name: 'Test Key', scopes: ['links:read'] });

      const insertedPrefix = repo.insert.mock.calls[0][0].key_prefix;
      expect(insertedPrefix).toMatch(/^qx_live_/);
    });
  });

  // -------------------------------------------------------------------------
  // list
  // -------------------------------------------------------------------------

  describe('list', () => {
    it('returns mapped public records without key_hash', async () => {
      const record = makeRecord();
      repo.findAll.mockResolvedValue([record]);

      const result = await service.list();

      expect(result).toHaveLength(1);
      expect(result[0]).not.toHaveProperty('key_hash');
      expect(result[0]).not.toHaveProperty('updated_at');
      expect(result[0].id).toBe(record.id);
    });

    it('forwards owner_id filter to repository', async () => {
      repo.findAll.mockResolvedValue([]);
      await service.list('wallet-abc');
      expect(repo.findAll).toHaveBeenCalledWith('wallet-abc');
    });
  });

  // -------------------------------------------------------------------------
  // revoke
  // -------------------------------------------------------------------------

  describe('revoke', () => {
    it('calls repo.revoke when key exists', async () => {
      repo.findById.mockResolvedValue(makeRecord());
      repo.revoke.mockResolvedValue(undefined);

      await service.revoke('test-uuid-1234');

      expect(repo.revoke).toHaveBeenCalledWith('test-uuid-1234');
    });

    it('throws NotFoundException when key does not exist', async () => {
      repo.findById.mockResolvedValue(null);

      await expect(service.revoke('missing-id')).rejects.toThrow(
        NotFoundException,
      );
      expect(repo.revoke).not.toHaveBeenCalled();
    });
  });

  // -------------------------------------------------------------------------
  // rotate
  // -------------------------------------------------------------------------

  describe('rotate', () => {
    it('returns a new raw key and updated record', async () => {
      const original = makeRecord({ key_prefix: 'qx_live_old' });
      const updated = makeRecord({ key_prefix: 'qx_live_new' });
      repo.findById.mockResolvedValue(original);
      repo.updateKey.mockResolvedValue(updated);

      const result = await service.rotate('test-uuid-1234');

      expect(result.key).toMatch(/^qx_live_[a-f0-9]+$/);
      expect(repo.updateKey).toHaveBeenCalledWith(
        'test-uuid-1234',
        expect.objectContaining({ key_hash: expect.stringMatching(/^\$2b\$/) }),
      );
    });

    it('throws NotFoundException when key does not exist', async () => {
      repo.findById.mockResolvedValue(null);

      await expect(service.rotate('missing-id')).rejects.toThrow(
        NotFoundException,
      );
    });
  });

  // -------------------------------------------------------------------------
  // validateKey
  // -------------------------------------------------------------------------

  describe('validateKey', () => {
    it('returns null when no candidates match the prefix', async () => {
      repo.findByPrefix.mockResolvedValue([]);

      const result = await service.validateKey('qx_live_abc123fakekeyvalue');

      expect(result).toBeNull();
    });

    it('returns null when prefix matches but bcrypt compare fails', async () => {
      // Store a hash for a different key so compare will fail
      const record = makeRecord({
        key_hash: '$2b$10$invalidhashvalue000000000000000000000000000000000000000',
      });
      repo.findByPrefix.mockResolvedValue([record]);
      repo.incrementUsage.mockResolvedValue(undefined);

      const result = await service.validateKey('qx_live_wrongkey12345678901234567890123456789012345678');

      expect(result).toBeNull();
    });
  });

  // -------------------------------------------------------------------------
  // isOverQuota
  // -------------------------------------------------------------------------

  describe('isOverQuota', () => {
    it('returns false when usage is below quota', () => {
      const record = makeRecord({ request_count: 5000, monthly_quota: 10000 });
      expect(service.isOverQuota(record)).toBe(false);
    });

    it('returns true when usage equals quota', () => {
      const record = makeRecord({ request_count: 10000, monthly_quota: 10000 });
      expect(service.isOverQuota(record)).toBe(true);
    });

    it('returns true when usage exceeds quota', () => {
      const record = makeRecord({ request_count: 10001, monthly_quota: 10000 });
      expect(service.isOverQuota(record)).toBe(true);
    });
  });
});
