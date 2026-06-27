import { Test, TestingModule } from '@nestjs/testing';
import { NotFoundException } from '@nestjs/common';
import { DeploymentSyncService } from '../deployment-sync.service';
import { SupabaseService } from '../../supabase/supabase.service';
import { DeploymentWebhookPayloadDto } from '../dto/webhook-payload.dto';

describe('DeploymentSyncService', () => {
  let service: DeploymentSyncService;
  let supabaseServiceMock: jest.Mocked<Partial<SupabaseService>>;

  const mockQueryBuilder: any = {};

  beforeEach(async () => {
    mockQueryBuilder.select = jest.fn().mockReturnValue(mockQueryBuilder);
    mockQueryBuilder.eq = jest.fn().mockReturnValue(mockQueryBuilder);
    mockQueryBuilder.maybeSingle = jest.fn();
    mockQueryBuilder.order = jest.fn().mockReturnValue(mockQueryBuilder);
    mockQueryBuilder.upsert = jest.fn().mockReturnValue(mockQueryBuilder);
    mockQueryBuilder.single = jest.fn();

    const mockSupabaseClient = {
      from: jest.fn().mockReturnValue(mockQueryBuilder),
    };

    supabaseServiceMock = {
      getClient: jest.fn().mockReturnValue(mockSupabaseClient),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        DeploymentSyncService,
        {
          provide: SupabaseService,
          useValue: supabaseServiceMock,
        },
      ],
    }).compile();

    service = module.get<DeploymentSyncService>(DeploymentSyncService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('syncDeployment', () => {
    const payload: DeploymentWebhookPayloadDto = {
      branchName: 'feat/be-branch-metadata-sync',
      prNumber: 42,
      commitSha: 'a1b2c3d4e5f6g7h8i9j0a1b2c3d4e5f6g7h8i9j0',
      previewUrl: 'https://quickex-preview-pr-42.vercel.app',
      status: 'success',
      eventTimestamp: '2026-06-27T08:00:00.000Z',
    };

    it('should successfully sync a new deployment (no existing record)', async () => {
      // Mock: no existing record found
      mockQueryBuilder.maybeSingle.mockResolvedValueOnce({ data: null, error: null });

      const dbResponse = {
        id: 'uuid-123',
        branch_name: payload.branchName,
        pr_number: payload.prNumber,
        commit_sha: payload.commitSha,
        preview_url: payload.previewUrl,
        status: payload.status,
        event_timestamp: payload.eventTimestamp,
        created_at: '2026-06-27T08:00:05.000Z',
        updated_at: '2026-06-27T08:00:05.000Z',
      };

      // Mock: upsert success
      mockQueryBuilder.single.mockResolvedValueOnce({ data: dbResponse, error: null });

      const result = await service.syncDeployment(payload);

      expect(mockQueryBuilder.select).toHaveBeenCalled();
      expect(mockQueryBuilder.eq).toHaveBeenCalledWith('branch_name', payload.branchName);
      expect(mockQueryBuilder.upsert).toHaveBeenCalledWith(
        expect.objectContaining({
          branch_name: payload.branchName,
          commit_sha: payload.commitSha,
          status: payload.status,
        }),
        { onConflict: 'branch_name' }
      );
      expect(result).toEqual({
        id: 'uuid-123',
        branchName: payload.branchName,
        prNumber: payload.prNumber,
        commitSha: payload.commitSha,
        previewUrl: payload.previewUrl,
        status: payload.status,
        eventTimestamp: payload.eventTimestamp,
        createdAt: '2026-06-27T08:00:05.000Z',
        updatedAt: '2026-06-27T08:00:05.000Z',
      });
    });

    it('should successfully update an existing record if the incoming event is newer', async () => {
      const existingRecord = {
        id: 'uuid-123',
        branch_name: payload.branchName,
        pr_number: payload.prNumber,
        commit_sha: 'old-commit-sha',
        preview_url: payload.previewUrl,
        status: 'pending',
        event_timestamp: '2026-06-27T07:50:00.000Z', // 10 minutes older
        created_at: '2026-06-27T07:50:05.000Z',
        updated_at: '2026-06-27T07:50:05.000Z',
      };

      mockQueryBuilder.maybeSingle.mockResolvedValueOnce({ data: existingRecord, error: null });

      const updatedRecord = {
        ...existingRecord,
        commit_sha: payload.commitSha,
        status: payload.status,
        event_timestamp: payload.eventTimestamp,
        updated_at: '2026-06-27T08:00:05.000Z',
      };

      mockQueryBuilder.single.mockResolvedValueOnce({ data: updatedRecord, error: null });

      const result = await service.syncDeployment(payload);

      expect(mockQueryBuilder.upsert).toHaveBeenCalled();
      expect(result.status).toBe('success');
      expect(result.commitSha).toBe(payload.commitSha);
    });

    it('should discard the update (noop) and return existing data if the incoming event is older (stale)', async () => {
      const existingRecord = {
        id: 'uuid-123',
        branch_name: payload.branchName,
        pr_number: payload.prNumber,
        commit_sha: payload.commitSha,
        preview_url: payload.previewUrl,
        status: payload.status,
        event_timestamp: '2026-06-27T08:10:00.000Z', // 10 minutes newer than incoming event
        created_at: '2026-06-27T08:10:05.000Z',
        updated_at: '2026-06-27T08:10:05.000Z',
      };

      mockQueryBuilder.maybeSingle.mockResolvedValueOnce({ data: existingRecord, error: null });

      const result = await service.syncDeployment(payload);

      // Should check but NOT upsert
      expect(mockQueryBuilder.upsert).not.toHaveBeenCalled();
      expect(result.eventTimestamp).toBe('2026-06-27T08:10:00.000Z');
    });

    it('should update and be idempotent on duplicate delivery (same timestamp)', async () => {
      const existingRecord = {
        id: 'uuid-123',
        branch_name: payload.branchName,
        pr_number: payload.prNumber,
        commit_sha: payload.commitSha,
        preview_url: payload.previewUrl,
        status: payload.status,
        event_timestamp: payload.eventTimestamp, // identical timestamp
        created_at: '2026-06-27T08:00:05.000Z',
        updated_at: '2026-06-27T08:00:05.000Z',
      };

      mockQueryBuilder.maybeSingle.mockResolvedValueOnce({ data: existingRecord, error: null });
      mockQueryBuilder.single.mockResolvedValueOnce({ data: existingRecord, error: null });

      const result = await service.syncDeployment(payload);

      expect(mockQueryBuilder.upsert).toHaveBeenCalled();
      expect(result.eventTimestamp).toBe(payload.eventTimestamp);
    });

    it('should throw an error if database select fails', async () => {
      mockQueryBuilder.maybeSingle.mockResolvedValueOnce({
        data: null,
        error: { message: 'Database connection failed' },
      });

      await expect(service.syncDeployment(payload)).rejects.toThrow(
        'Database error fetching deployment metadata: Database connection failed'
      );
    });

    it('should throw an error if database upsert fails', async () => {
      mockQueryBuilder.maybeSingle.mockResolvedValueOnce({ data: null, error: null });
      mockQueryBuilder.single.mockResolvedValueOnce({
        data: null,
        error: { message: 'Insert failed due to constraint' },
      });

      await expect(service.syncDeployment(payload)).rejects.toThrow(
        'Database error upserting deployment metadata: Insert failed due to constraint'
      );
    });
  });

  describe('getDeploymentByBranch', () => {
    it('should return mapped DTO if record exists', async () => {
      const record = {
        id: 'uuid-123',
        branch_name: 'main',
        pr_number: null,
        commit_sha: 'commit-123',
        preview_url: null,
        status: 'success',
        event_timestamp: '2026-06-27T08:00:00.000Z',
        created_at: '2026-06-27T08:00:05.000Z',
        updated_at: '2026-06-27T08:00:05.000Z',
      };

      mockQueryBuilder.maybeSingle.mockResolvedValueOnce({ data: record, error: null });

      const result = await service.getDeploymentByBranch('main');

      expect(mockQueryBuilder.eq).toHaveBeenCalledWith('branch_name', 'main');
      expect(result.branchName).toBe('main');
      expect(result.commitSha).toBe('commit-123');
    });

    it('should throw NotFoundException if record does not exist', async () => {
      mockQueryBuilder.maybeSingle.mockResolvedValueOnce({ data: null, error: null });

      await expect(service.getDeploymentByBranch('non-existent')).rejects.toThrow(NotFoundException);
    });
  });

  describe('getDeploymentsByPr', () => {
    it('should return list of mapped DTOs if records exist', async () => {
      const records = [
        {
          id: 'uuid-123',
          branch_name: 'feat/one',
          pr_number: 42,
          commit_sha: 'sha-1',
          preview_url: null,
          status: 'success',
          event_timestamp: '2026-06-27T08:00:00.000Z',
          created_at: '2026-06-27T08:00:05.000Z',
          updated_at: '2026-06-27T08:00:05.000Z',
        },
      ];

      mockQueryBuilder.order.mockResolvedValueOnce({ data: records, error: null });

      const result = await service.getDeploymentsByPr(42);

      expect(mockQueryBuilder.eq).toHaveBeenCalledWith('pr_number', 42);
      expect(mockQueryBuilder.order).toHaveBeenCalledWith('event_timestamp', { ascending: false });
      expect(result).toHaveLength(1);
      expect(result[0].branchName).toBe('feat/one');
    });

    it('should throw NotFoundException if no records exist', async () => {
      mockQueryBuilder.order.mockResolvedValueOnce({ data: [], error: null });

      await expect(service.getDeploymentsByPr(999)).rejects.toThrow(NotFoundException);
    });
  });
});
