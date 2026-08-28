import { Test, TestingModule } from '@nestjs/testing';
import { ExportRepository } from '../export.repository';
import { SupabaseService } from '../../supabase/supabase.service';
import {
  ExportDeliveryMethod,
  ExportFormat,
  ExportStatus,
  ExportType,
} from '../enums/export.enums';
import {
  ExportInvalidTransitionError,
  ExportJobRow,
  ExportRecordNotFoundError,
} from '../types/export.types';
import { EXPORT_JOBS_TABLE } from '../constants/export.constants';

function makeRow(overrides: Partial<ExportJobRow> = {}): ExportJobRow {
  return {
    id: 'rec-1',
    job_id: 'job-1',
    user_id: 'GUSER123',
    export_type: ExportType.TRANSACTIONS,
    format: ExportFormat.CSV,
    delivery_method: ExportDeliveryMethod.EMAIL,
    filters: {},
    status: ExportStatus.QUEUED,
    delivery_reference: null,
    failure_reason: null,
    queued_at: '2026-08-28T12:00:00.000Z',
    started_at: null,
    completed_at: null,
    failed_at: null,
    created_at: '2026-08-28T12:00:00.000Z',
    updated_at: '2026-08-28T12:00:00.000Z',
    ...overrides,
  };
}

function createChain(result: { data: unknown; error: unknown }) {
  const chain: Record<string, jest.Mock> = {};
  chain.insert = jest.fn().mockReturnValue(chain);
  chain.update = jest.fn().mockReturnValue(chain);
  chain.select = jest.fn().mockReturnValue(chain);
  chain.eq = jest.fn().mockReturnValue(chain);
  chain.maybeSingle = jest.fn().mockResolvedValue(result);
  chain.single = jest.fn().mockResolvedValue(result);
  return chain;
}

describe('ExportRepository', () => {
  let repository: ExportRepository;
  let from: jest.Mock;

  beforeEach(async () => {
    from = jest.fn();

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ExportRepository,
        {
          provide: SupabaseService,
          useValue: {
            getClient: jest.fn(() => ({ from })),
          },
        },
      ],
    }).compile();

    repository = module.get(ExportRepository);
  });

  describe('create', () => {
    it('persists a queued export record', async () => {
      const row = makeRow();
      const chain = createChain({ data: row, error: null });
      from.mockReturnValue(chain);

      const record = await repository.create({
        jobId: 'job-1',
        userId: 'GUSER123',
        exportType: ExportType.TRANSACTIONS,
        format: ExportFormat.CSV,
        deliveryMethod: ExportDeliveryMethod.EMAIL,
        filters: {},
      });

      expect(from).toHaveBeenCalledWith(EXPORT_JOBS_TABLE);
      expect(chain.insert).toHaveBeenCalledWith(
        expect.objectContaining({
          job_id: 'job-1',
          status: ExportStatus.QUEUED,
          user_id: 'GUSER123',
        }),
      );
      expect(record.status).toBe(ExportStatus.QUEUED);
      expect(record.jobId).toBe('job-1');
    });
  });

  describe('status transitions', () => {
    it('transitions queued -> running and stamps startedAt', async () => {
      const queued = makeRow();
      const running = makeRow({
        status: ExportStatus.RUNNING,
        started_at: '2026-08-28T12:01:00.000Z',
      });

      const findChain = createChain({ data: queued, error: null });
      const updateChain = createChain({ data: running, error: null });
      from.mockReturnValueOnce(findChain).mockReturnValueOnce(updateChain);

      const record = await repository.transition('job-1', ExportStatus.RUNNING);

      expect(updateChain.update).toHaveBeenCalledWith(
        expect.objectContaining({
          status: ExportStatus.RUNNING,
          started_at: expect.any(String),
        }),
      );
      expect(record.status).toBe(ExportStatus.RUNNING);
      expect(record.startedAt).toBeInstanceOf(Date);
    });

    it('transitions running -> completed with delivery reference and timestamp', async () => {
      const running = makeRow({
        status: ExportStatus.RUNNING,
        started_at: '2026-08-28T12:01:00.000Z',
      });
      const completed = makeRow({
        status: ExportStatus.COMPLETED,
        started_at: '2026-08-28T12:01:00.000Z',
        completed_at: '2026-08-28T12:02:00.000Z',
        delivery_reference: 'email:export:job-1',
      });

      const findChain = createChain({ data: running, error: null });
      const updateChain = createChain({ data: completed, error: null });
      from.mockReturnValueOnce(findChain).mockReturnValueOnce(updateChain);

      const record = await repository.transition('job-1', ExportStatus.COMPLETED, {
        deliveryReference: 'email:export:job-1',
      });

      expect(updateChain.update).toHaveBeenCalledWith(
        expect.objectContaining({
          status: ExportStatus.COMPLETED,
          delivery_reference: 'email:export:job-1',
          completed_at: expect.any(String),
        }),
      );
      expect(record.status).toBe(ExportStatus.COMPLETED);
      expect(record.deliveryReference).toBe('email:export:job-1');
    });

    it('transitions running -> failed with failure reason and timestamp', async () => {
      const running = makeRow({
        status: ExportStatus.RUNNING,
        started_at: '2026-08-28T12:01:00.000Z',
      });
      const failed = makeRow({
        status: ExportStatus.FAILED,
        started_at: '2026-08-28T12:01:00.000Z',
        failed_at: '2026-08-28T12:02:00.000Z',
        failure_reason: 'query failed',
      });

      const findChain = createChain({ data: running, error: null });
      const updateChain = createChain({ data: failed, error: null });
      from.mockReturnValueOnce(findChain).mockReturnValueOnce(updateChain);

      const record = await repository.transition('job-1', ExportStatus.FAILED, {
        failureReason: 'query failed',
      });

      expect(updateChain.update).toHaveBeenCalledWith(
        expect.objectContaining({
          status: ExportStatus.FAILED,
          failure_reason: 'query failed',
          failed_at: expect.any(String),
        }),
      );
      expect(record.status).toBe(ExportStatus.FAILED);
      expect(record.failureReason).toBe('query failed');
    });

    it('allows queued -> failed without going through running', async () => {
      const queued = makeRow();
      const failed = makeRow({
        status: ExportStatus.FAILED,
        failed_at: '2026-08-28T12:01:00.000Z',
        failure_reason: 'persist failed',
      });

      const findChain = createChain({ data: queued, error: null });
      const updateChain = createChain({ data: failed, error: null });
      from.mockReturnValueOnce(findChain).mockReturnValueOnce(updateChain);

      const record = await repository.transition('job-1', ExportStatus.FAILED, {
        failureReason: 'persist failed',
      });

      expect(record.status).toBe(ExportStatus.FAILED);
    });

    it('is idempotent when transitioning to the current status', async () => {
      const running = makeRow({ status: ExportStatus.RUNNING });
      const findChain = createChain({ data: running, error: null });
      from.mockReturnValueOnce(findChain);

      const record = await repository.transition('job-1', ExportStatus.RUNNING);

      expect(record.status).toBe(ExportStatus.RUNNING);
      expect(from).toHaveBeenCalledTimes(1);
    });

    it('rejects an invalid transition from completed to running', async () => {
      const completed = makeRow({ status: ExportStatus.COMPLETED });
      const findChain = createChain({ data: completed, error: null });
      from.mockReturnValueOnce(findChain);

      await expect(
        repository.transition('job-1', ExportStatus.RUNNING),
      ).rejects.toThrow(ExportInvalidTransitionError);
    });

    it('rejects an invalid transition from failed to completed', async () => {
      const failed = makeRow({ status: ExportStatus.FAILED });
      const findChain = createChain({ data: failed, error: null });
      from.mockReturnValueOnce(findChain);

      await expect(
        repository.transition('job-1', ExportStatus.COMPLETED),
      ).rejects.toThrow(ExportInvalidTransitionError);
    });

    it('throws when the export record does not exist', async () => {
      const findChain = createChain({ data: null, error: null });
      from.mockReturnValueOnce(findChain);

      await expect(
        repository.transition('missing', ExportStatus.RUNNING),
      ).rejects.toThrow(ExportRecordNotFoundError);
    });
  });
});
