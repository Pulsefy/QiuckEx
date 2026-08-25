/**
 * Sep24StatusPollHandler – Unit Tests
 *
 * Verifies:
 *  - execute() delegates to Sep24PollingService.runPollCycle()
 *  - validate() accepts valid payloads and rejects invalid ones
 *  - onFailure() logs without throwing
 */

import { Test, TestingModule } from '@nestjs/testing';
import { Sep24StatusPollHandler } from './sep24-status-poll.handler';
import { Sep24PollingService } from '../../fiat-ramps/sep24-polling.service';
import { PermanentJobError } from './webhook-delivery.handler';
import { Job, JobStatus, JobType } from '../types';
import { Sep24StatusPollPayload } from '../types/job-payloads.types';
import { CancellationStore } from '../cancellation-token';

const mockPollingService = {
  runPollCycle: jest.fn(),
};

function makeJob(triggeredBy: 'cron' | 'manual' = 'cron'): Job<Sep24StatusPollPayload> {
  return {
    id: 'job-sep24-1',
    type: JobType.SEP24_STATUS_POLL,
    payload: { triggeredBy },
    status: JobStatus.RUNNING,
    attempts: 0,
    maxAttempts: 1,
    createdAt: new Date(),
    scheduledAt: new Date(),
    startedAt: new Date(),
    completedAt: null,
    failureReason: null,
    visibilityTimeout: null,
  };
}

function makeCancellationToken() {
  const store = new CancellationStore();
  return store.createToken('job-sep24-1');
}

describe('Sep24StatusPollHandler', () => {
  let handler: Sep24StatusPollHandler;

  beforeEach(async () => {
    jest.clearAllMocks();

    mockPollingService.runPollCycle.mockResolvedValue({
      processed: 5,
      updated: 3,
      terminal: 1,
      stuck: 0,
      failed: 1,
    });

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        Sep24StatusPollHandler,
        { provide: Sep24PollingService, useValue: mockPollingService },
      ],
    }).compile();

    handler = module.get<Sep24StatusPollHandler>(Sep24StatusPollHandler);
  });

  // ── execute ────────────────────────────────────────────────────────────────

  describe('execute', () => {
    it('calls runPollCycle and resolves successfully', async () => {
      const job = makeJob('cron');
      const token = makeCancellationToken();

      await expect(handler.execute(job, token)).resolves.toBeUndefined();
      expect(mockPollingService.runPollCycle).toHaveBeenCalledTimes(1);
    });

    it('works with triggeredBy=manual', async () => {
      const job = makeJob('manual');
      const token = makeCancellationToken();

      await expect(handler.execute(job, token)).resolves.toBeUndefined();
      expect(mockPollingService.runPollCycle).toHaveBeenCalledTimes(1);
    });

    it('rethrows errors from runPollCycle so the job is marked failed', async () => {
      const job = makeJob('cron');
      const token = makeCancellationToken();

      mockPollingService.runPollCycle.mockRejectedValue(new Error('Horizon unavailable'));

      await expect(handler.execute(job, token)).rejects.toThrow('Horizon unavailable');
    });
  });

  // ── validate ──────────────────────────────────────────────────────────────

  describe('validate', () => {
    it('accepts cron triggeredBy', async () => {
      await expect(handler.validate({ triggeredBy: 'cron' })).resolves.toBeUndefined();
    });

    it('accepts manual triggeredBy', async () => {
      await expect(handler.validate({ triggeredBy: 'manual' })).resolves.toBeUndefined();
    });

    it('throws PermanentJobError for invalid triggeredBy', async () => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      await expect(handler.validate({ triggeredBy: 'unknown' as any })).rejects.toThrow(
        PermanentJobError,
      );
    });

    it('throws PermanentJobError for missing triggeredBy', async () => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      await expect(handler.validate({} as any)).rejects.toThrow(PermanentJobError);
    });
  });

  // ── onFailure ─────────────────────────────────────────────────────────────

  describe('onFailure', () => {
    it('resolves without throwing', async () => {
      const job = makeJob('cron');
      await expect(
        handler.onFailure(job, new Error('Poll cycle failed')),
      ).resolves.toBeUndefined();
    });
  });
});
