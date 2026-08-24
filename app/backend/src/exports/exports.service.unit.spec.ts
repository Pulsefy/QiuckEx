import { Test, TestingModule } from '@nestjs/testing';
import { BadRequestException, ForbiddenException, NotFoundException } from '@nestjs/common';
import * as crypto from 'crypto';
import { ExportsService } from './exports.service';
import { SupabaseService } from '../supabase/supabase.service';
import { AppConfigService } from '../config/app-config.service';

describe('ExportsService', () => {
  let service: ExportsService;
  let supabaseService: SupabaseService;
  let appConfig: AppConfigService;
  let mockSupabaseClient: any;
  let mockStorageFrom: any;

  const mockConfig = {
    exportBucket: 'test-exports',
    exportRetentionDays: 7,
    exportSigningSecret: 'test-signing-secret',
    exportLinkTtlSeconds: 3600,
    apiBaseUrl: 'http://localhost:3000',
  };

  beforeEach(async () => {
    mockStorageFrom = {
      upload: jest.fn().mockResolvedValue({ error: null }),
      download: jest.fn(),
      list: jest.fn(),
      remove: jest.fn().mockResolvedValue({ error: null }),
    };

    mockSupabaseClient = {
      storage: {
        from: jest.fn().mockReturnValue(mockStorageFrom),
        getBucket: jest.fn().mockResolvedValue({ data: { name: 'test-exports' }, error: null }),
        createBucket: jest.fn().mockResolvedValue({ error: null }),
      },
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ExportsService,
        {
          provide: SupabaseService,
          useValue: {
            getClient: jest.fn().mockReturnValue(mockSupabaseClient),
          },
        },
        {
          provide: AppConfigService,
          useValue: mockConfig,
        },
      ],
    }).compile();

    service = module.get<ExportsService>(ExportsService);
    supabaseService = module.get<SupabaseService>(SupabaseService);
    appConfig = module.get<AppConfigService>(AppConfigService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('uploadExportArtifact', () => {
    it('should upload export data and return key', async () => {
      const userId = 'user-123';
      const jobId = 'job-456';
      const content = 'col1,col2\nval1,val2';
      const format = 'csv';

      const key = await service.uploadExportArtifact(userId, jobId, content, format);

      expect(key).toBe(`exports/${userId}/${jobId}.csv`);
      expect(mockSupabaseClient.storage.from).toHaveBeenCalledWith('test-exports');
      expect(mockStorageFrom.upload).toHaveBeenCalledWith(
        key,
        Buffer.from(content),
        expect.objectContaining({
          contentType: 'text/csv',
          upsert: true,
        }),
      );
    });

    it('should create bucket if it does not exist', async () => {
      mockSupabaseClient.storage.getBucket.mockResolvedValue({ data: null, error: new Error('Not found') });

      await service.uploadExportArtifact('user-123', 'job-456', '{}', 'json');

      expect(mockSupabaseClient.storage.createBucket).toHaveBeenCalledWith('test-exports', { public: false });
    });

    it('should throw error if upload fails', async () => {
      mockStorageFrom.upload.mockResolvedValue({ error: { message: 'Upload failed' } });

      await expect(
        service.uploadExportArtifact('user-123', 'job-456', '{}', 'json'),
      ).rejects.toThrow('Failed to store export artifact: Upload failed');
    });
  });

  describe('generateSignedDownloadUrl', () => {
    it('should return a valid signed download URL', () => {
      const userId = 'user-123';
      const jobId = 'job-456';
      const format = 'csv';

      const urlString = service.generateSignedDownloadUrl(userId, jobId, format);
      const url = new URL(urlString);

      expect(url.origin).toBe('http://localhost:3000');
      expect(url.pathname).toBe('/exports/download');
      expect(url.searchParams.get('userId')).toBe(userId);
      expect(url.searchParams.get('jobId')).toBe(jobId);
      expect(url.searchParams.get('format')).toBe(format);
      
      const expiresAt = url.searchParams.get('expiresAt')!;
      expect(new Date(expiresAt).getTime()).toBeGreaterThan(Date.now());

      const signature = url.searchParams.get('signature')!;
      const expectedMessage = `${userId}:${jobId}:${expiresAt}`;
      const expectedSignature = crypto
        .createHmac('sha256', mockConfig.exportSigningSecret)
        .update(expectedMessage)
        .digest('hex');

      expect(signature).toBe(expectedSignature);
    });
  });

  describe('verifyAndRetrieveArtifact', () => {
    const userId = 'user-123';
    const jobId = 'job-456';
    const format = 'csv';
    let expiresAt: string;
    let signature: string;

    beforeEach(() => {
      expiresAt = new Date(Date.now() + 3600 * 1000).toISOString();
      const message = `${userId}:${jobId}:${expiresAt}`;
      signature = crypto
        .createHmac('sha256', mockConfig.exportSigningSecret)
        .update(message)
        .digest('hex');
    });

    it('should verify and retrieve artifact successfully', async () => {
      const mockCsvContent = 'col1,col2\nval1,val2';
      const arrayBufferMock = jest.fn().mockResolvedValue(Buffer.from(mockCsvContent));
      const blobMock = {
        arrayBuffer: arrayBufferMock,
      };
      mockStorageFrom.download.mockResolvedValue({ data: blobMock, error: null });

      const result = await service.verifyAndRetrieveArtifact(
        { userId, jobId, format, expiresAt, signature },
        userId,
      );

      expect(result.contentType).toBe('text/csv');
      expect(result.data.toString()).toBe(mockCsvContent);
      expect(mockSupabaseClient.storage.from).toHaveBeenCalledWith('test-exports');
      expect(mockStorageFrom.download).toHaveBeenCalledWith(`exports/${userId}/${jobId}.csv`);
    });

    it('should reject tampered signature with URL_INVALID error code', async () => {
      const badSignature = signature + 'tampered';

      await expect(
        service.verifyAndRetrieveArtifact(
          { userId, jobId, format, expiresAt, signature: badSignature },
          userId,
        ),
      ).rejects.toThrow(
        new BadRequestException({
          error: 'URL_INVALID',
          message: 'Download URL is invalid or has been tampered with',
        }),
      );
    });

    it('should reject expired link with URL_EXPIRED error code', async () => {
      const expiredTime = new Date(Date.now() - 1000).toISOString();
      const expiredMessage = `${userId}:${jobId}:${expiredTime}`;
      const expiredSignature = crypto
        .createHmac('sha256', mockConfig.exportSigningSecret)
        .update(expiredMessage)
        .digest('hex');

      await expect(
        service.verifyAndRetrieveArtifact(
          { userId, jobId, format, expiresAt: expiredTime, signature: expiredSignature },
          userId,
        ),
      ).rejects.toThrow(
        new BadRequestException({
          error: 'URL_EXPIRED',
          message: 'Download URL has expired',
        }),
      );
    });

    it('should reject mismatched principal with UNAUTHORIZED_ACCESS error code', async () => {
      await expect(
        service.verifyAndRetrieveArtifact(
          { userId, jobId, format, expiresAt, signature },
          'unauthorized-user-999',
        ),
      ).rejects.toThrow(
        new ForbiddenException({
          error: 'UNAUTHORIZED_ACCESS',
          message: 'You are not authorized to download this export',
        }),
      );
    });

    it('should throw NotFoundException if file download fails', async () => {
      mockStorageFrom.download.mockResolvedValue({ data: null, error: { message: 'Not found' } });

      await expect(
        service.verifyAndRetrieveArtifact(
          { userId, jobId, format, expiresAt, signature },
          userId,
        ),
      ).rejects.toThrow(
        new NotFoundException({
          error: 'ARTIFACT_NOT_FOUND',
          message: 'Export file not found in storage',
        }),
      );
    });
  });

  describe('cleanupExpiredArtifacts', () => {
    it('should clean up files older than retention days', async () => {
      const now = Date.now();

      mockStorageFrom.list.mockImplementation((path: string) => {
        if (path === 'exports') {
          return Promise.resolve({
            data: [{ name: 'user-1' }, { name: 'user-2' }],
            error: null,
          });
        }
        if (path === 'exports/user-1') {
          return Promise.resolve({
            data: [{ name: 'old.csv', created_at: new Date(now - 10 * 24 * 60 * 60 * 1000).toISOString() }],
            error: null,
          });
        }
        if (path === 'exports/user-2') {
          return Promise.resolve({
            data: [{ name: 'new.csv', created_at: new Date(now - 2 * 24 * 60 * 60 * 1000).toISOString() }],
            error: null,
          });
        }
        return Promise.resolve({ data: [], error: null });
      });

      await service.cleanupExpiredArtifacts();

      expect(mockStorageFrom.list).toHaveBeenCalledWith('exports');
      expect(mockStorageFrom.list).toHaveBeenCalledWith('exports/user-1');
      expect(mockStorageFrom.list).toHaveBeenCalledWith('exports/user-2');
      expect(mockStorageFrom.remove).toHaveBeenCalledWith(['exports/user-1/old.csv']);
    });

    it('should not call remove if no files are expired', async () => {
      const now = Date.now();

      mockStorageFrom.list.mockImplementation((path: string) => {
        if (path === 'exports') {
          return Promise.resolve({
            data: [{ name: 'user-2' }],
            error: null,
          });
        }
        if (path === 'exports/user-2') {
          return Promise.resolve({
            data: [{ name: 'new.csv', created_at: new Date(now - 1 * 24 * 60 * 60 * 1000).toISOString() }],
            error: null,
          });
        }
        return Promise.resolve({ data: [], error: null });
      });

      await service.cleanupExpiredArtifacts();

      expect(mockStorageFrom.remove).not.toHaveBeenCalled();
    });
  });
});
