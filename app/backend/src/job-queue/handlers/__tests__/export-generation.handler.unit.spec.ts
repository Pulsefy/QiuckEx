import { Test, TestingModule } from '@nestjs/testing';
import { ExportGenerationHandler } from '../export-generation.handler';
import { SupabaseService } from '../../../supabase/supabase.service';
import { ExportsService } from '../../../exports/exports.service';
import { Job, CancellationToken, JobStatus } from '../../../job-queue/types';
import { ExportGenerationPayload } from '../../../job-queue/types/job-payloads.types';

describe('ExportGenerationHandler', () => {
  let handler: ExportGenerationHandler;
  let supabaseService: SupabaseService;
  let exportsService: ExportsService;
  let mockSupabaseClient: any;
  let mockQuery: any;

  const mockJob: Job<ExportGenerationPayload> = {
    id: 'job-123',
    type: 'EXPORT_GENERATION' as any,
    payload: {
      userId: 'user-123',
      exportType: 'transactions',
      format: 'csv',
      deliveryMethod: 'download',
      filters: { status: 'completed' },
    },
    status: JobStatus.PENDING,
    attempts: 0,
    maxAttempts: 3,
    createdAt: new Date(),
    scheduledAt: new Date(),
    startedAt: null,
    completedAt: null,
    failureReason: null,
    visibilityTimeout: null,
  };

  const mockCancellationToken: CancellationToken = {
    throwIfCancelled: jest.fn(),
    isCancelled: jest.fn().mockReturnValue(false),
  };

  beforeEach(async () => {
    mockQuery = {
      select: jest.fn().mockReturnThis(),
      eq: jest.fn().mockReturnThis(),
    };

    // Ensure the query is thenable to mock Supabase's Promise-like query builder
    mockQuery.then = (resolve: any) =>
      resolve({
        data: [{ id: 'tx-1', amount: '100', user_id: 'user-123', status: 'completed' }],
        error: null,
      });

    mockSupabaseClient = {
      from: jest.fn().mockReturnValue(mockQuery),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ExportGenerationHandler,
        {
          provide: SupabaseService,
          useValue: {
            getClient: jest.fn().mockReturnValue(mockSupabaseClient),
          },
        },
        {
          provide: ExportsService,
          useValue: {
            uploadExportArtifact: jest.fn().mockResolvedValue('exports/user-123/job-123.csv'),
            generateSignedDownloadUrl: jest.fn().mockReturnValue('http://localhost:3000/exports/download?sig=abc'),
          },
        },
      ],
    }).compile();

    handler = module.get<ExportGenerationHandler>(ExportGenerationHandler);
    supabaseService = module.get<SupabaseService>(SupabaseService);
    exportsService = module.get<ExportsService>(ExportsService);
  });

  it('should be defined', () => {
    expect(handler).toBeDefined();
  });

  describe('execute', () => {
    it('should query data, generate file, upload to storage, and generate signed URL', async () => {
      await handler.execute(mockJob, mockCancellationToken);

      expect(mockSupabaseClient.from).toHaveBeenCalledWith('transactions');
      expect(mockQuery.select).toHaveBeenCalledWith('*');
      expect(mockQuery.eq).toHaveBeenCalledWith('user_id', 'user-123');
      expect(mockQuery.eq).toHaveBeenCalledWith('status', 'completed');

      expect(exportsService.uploadExportArtifact).toHaveBeenCalledWith(
        'user-123',
        'job-123',
        expect.stringContaining('tx-1'),
        'csv',
      );

      expect(exportsService.generateSignedDownloadUrl).toHaveBeenCalledWith(
        'user-123',
        'job-123',
        'csv',
      );
    });
  });
});
